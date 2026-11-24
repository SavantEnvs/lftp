// Fuzzes the FTP client protocol engine (src/ftpclass.cc: reply parsing, the
// Expect queue, FEAT/PWD/PASV/EPSV handling, Ftp::SendCWD, the LIST data path)
// through the public FileAccess API, against an in-process fake server thread on
// a loopback socket that sends the fuzz input as its control-connection replies.
//
// Input: the first line is the directory the client "cd"s into (a relative,
// multi-component path reaches the non-URL branch of Ftp::SendCWD); the rest
// is the byte stream the server sends after accepting the connection. The
// server then closes its write side, so every session ends by EOF.
//
// State kept across inputs: only the ResMgr settings set once in
// LLVMFuzzerInitialize (never changed by an input). Each input gets a fresh
// listening socket, server thread and session, all destroyed before returning.
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
   ResMgr::Set("ftp:ssl-allow",0,"no");    // plain FTP only, no TLS handshake
   ResMgr::Set("ftp:sync-mode",0,"off");
   // settle the scheduler's start-up tasks before any session exists, as lftp's main() does
   SMTask::Schedule();
   return 0;
}

struct FakeServer {
   int lfd;
   const uint8_t *reply;
   size_t reply_len;
};

static void *serve(void *arg)
{
   FakeServer *fs=(FakeServer*)arg;
   int c=accept(fs->lfd,0,0);
   if(c<0)
      return 0;
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
   return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if(size>(1<<16))
      return 0;
   const uint8_t *nl=(const uint8_t*)memchr(data,'\n',size);
   size_t path_len=nl?nl-data:size;
   if(path_len==0 || path_len>512)
      return 0;
   xstring path((const char*)data,path_len);
   if(strlen(path)!=path_len)      // the cd argument is a C string
      return 0;

   char port[16];
   FakeServer fs;
   fs.lfd=make_listener(port,sizeof(port));
   if(fs.lfd<0)
      return 0;
   fs.reply=nl?nl+1:data+size;
   fs.reply_len=data+size-fs.reply;
   pthread_t th;
   if(pthread_create(&th,0,serve,&fs)!=0) {
      close(fs.lfd);
      return 0;
   }

   FileAccess *f=FileAccess::New("ftp","127.0.0.1",port);
   f->Login("user","pass");
   // FileAccess::fragile is never initialised by lftp (FileAccess.h; only SetFragile() writes
   // it), so Ftp::DisconnectNow() reads an indeterminate bool on every disconnect — a real
   // upstream bug, recorded in the PR. Set it through the public setter, as lftp's own copy
   // jobs do, so the target explores past it instead of stopping on it for every input.
   f->SetFragile();
   f->Open(path,FA::CHANGE_DIR);

   int phase=0;
   Buffer buf;
   int round=0;
   for(; round<100000; round++) {
      SMTask::Schedule();
      if(phase==0) {
	 int r=f->Done();
	 if(r!=FA::IN_PROGRESS) {
	    f->Close();
	    if(r!=FA::OK)
	       break;
	    f->Open("",FA::LONG_LIST);
	    phase=1;
	    continue;
	 }
      } else {
	 int r=f->Read(&buf,4096);
	 if(r>0) {
	    buf.SpaceAdd(r);
	    buf.Skip(r);
	    continue;
	 }
	 if(r!=FA::DO_AGAIN)
	    break;
      }
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
