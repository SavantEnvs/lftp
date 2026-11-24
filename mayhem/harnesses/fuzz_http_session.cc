// Fuzzes lftp's HTTP client response parser (src/Http.cc: the status line, Http::HandleHeaderLine,
// chunked transfer decoding, redirects/Location, Content-Range/-Length, WWW-Authenticate, and the
// HTML/WebDAV listing reached from a LONG_LIST) through the public FileAccess API, against an
// in-process fake server thread on a loopback socket that answers every request with the input.
//
// Input: byte 0 selects the operation (bit 0: LONG_LIST instead of RETRIEVE; bit 1: WebDAV
// PROPFIND listing, http:use-propfind); the rest is the raw response the server sends on each
// connection the client opens (lftp may reconnect after an error or auth challenge), then the
// server closes its write side, so every exchange ends by EOF.
//
// State kept across inputs: the ResMgr settings set in LLVMFuzzerInitialize (never changed by an
// input), plus
// http:use-propfind, which is set from byte 0 on every input (so never inherited). Cookies are
// not stored (http:set-cookies stays at its default "no"): lftp keeps them in the process-global
// ResMgr under input-chosen closures, which a harness cannot reset per input.
// Each input gets a fresh listening socket, server thread and session, all destroyed before
// returning.
#include "fuzz_common.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "FileAccess.h"
#include "ResMgr.h"
#include "buffer.h"
#include "log.h"

static int make_listener(char *port, size_t port_len)
{
   int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
   if(fd<0)
      return -1;
   struct sockaddr_in sa;
   memset(&sa,0,sizeof(sa));
   sa.sin_family=AF_INET;
   sa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
   socklen_t len=sizeof(sa);
   if(bind(fd,(struct sockaddr*)&sa,sizeof(sa))<0 || listen(fd,8)<0
   || getsockname(fd,(struct sockaddr*)&sa,&len)<0) {
      close(fd);
      return -1;
   }
   snprintf(port,port_len,"%u",(unsigned)ntohs(sa.sin_port));
   return fd;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   if(getenv("LFTP_FUZZ_DEBUG")) {
      Log::global=new Log("debug");
      ResMgr::Set("log:level",0,"9");
      ResMgr::Set("log:enabled",0,"true");
   }
   // no retries / reconnect delays: a session that loses its connection fails at once
   ResMgr::Set("net:max-retries",0,"1");
   ResMgr::Set("net:persist-retries",0,"0");
   ResMgr::Set("net:reconnect-interval-base",0,"0");
   ResMgr::Set("http:cache",0,"no");
   // Http waits for the rest of a header line even after the peer's EOF (Http.cc RECEIVING_HEADER:
   // a partial line with no newline is neither parsed nor treated as EOF) and only gives up on
   // lftp's own idle-connection timeout, net:timeout (default 5m). Every truncated response would
   // otherwise stall the session for 5 minutes; shorten lftp's own setting so the session ends
   // the way lftp ends it (CheckTimeout -> reconnect -> max-retries exceeded).
   ResMgr::Set("net:timeout",0,"0.5");
   // settle the scheduler's start-up tasks before any session exists, as lftp's main() does
   SMTask::Schedule();
   return 0;
}

struct FakeServer {
   int lfd;
   const uint8_t *reply;
   size_t reply_len;
};

static void serve_one(FakeServer *fs, int c)
{
   size_t sent=0;
   while(sent<fs->reply_len) {
      ssize_t w=write(c,fs->reply+sent,fs->reply_len-sent);
      if(w<=0)
	 break;
      sent+=w;
   }
   shutdown(c,SHUT_WR);
   char sink[4096];
   while(read(c,sink,sizeof(sink))>0)
      ;
   close(c);
}

// Answers every connection with the same bytes until the harness shuts the listener down, so a
// client reconnect (retry, redirect to the same host, auth round trip) never waits on a silent peer.
static void *serve(void *arg)
{
   FakeServer *fs=(FakeServer*)arg;
   for(;;) {
      int c=accept(fs->lfd,0,0);
      if(c<0)
	 return 0;
      serve_one(fs,c);
   }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if(size<1 || size>(1<<16))
      return -1;
   const uint8_t mode=data[0];
   ResMgr::Set("http:use-propfind",0,(mode&2)?"yes":"no");

   char port[16];
   FakeServer fs;
   fs.lfd=make_listener(port,sizeof(port));
   if(fs.lfd<0)
      return 0;
   fs.reply=data+1;
   fs.reply_len=size-1;
   pthread_t th;
   if(pthread_create(&th,0,serve,&fs)!=0) {
      close(fs.lfd);
      return 0;
   }

   FileAccess *f=FileAccess::New("http","127.0.0.1",port);
   // FileAccess::fragile is never initialised by lftp (FileAccess.h; only SetFragile() writes
   // it) and Http::DisconnectLL() reads it — the same upstream bug fuzz_ftp_session documents.
   f->SetFragile();
   if(mode&1)
      f->Open("/dir/",FA::LONG_LIST);
   else
      f->Open("/dir/file",FA::RETRIEVE);

   Buffer buf;
   for(int round=0; round<100000; round++) {
      SMTask::Schedule();
      int r=f->Read(&buf,4096);
      if(r>0) {
	 buf.SpaceAdd(r);
	 buf.Skip(r);
	 continue;
      }
      if(r!=FA::DO_AGAIN)
	 break;
      // Read() can drop the connection itself (short body -> Disconnect(), "retrying"); let the
      // session's Do() run once more so the poll set Block() waits on matches its new state.
      SMTask::Schedule();
      SMTask::Block();
   }
   f->Close();
   SMTask::Delete(f);
   SMTask::Schedule();
   shutdown(fs.lfd,SHUT_RDWR);
   pthread_join(th,0);
   close(fs.lfd);
   return 0;
}
