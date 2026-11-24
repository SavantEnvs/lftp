// Fuzzes lftp's .torrent metainfo handling (src/Torrent.cc) the way `torrent FILE` reaches it: a
// Torrent task reads the file through FileCopy, BeNode::Parse decodes it, Torrent::Do() walks the
// top-level dict (announce / announce-list trackers, DHT `nodes'), then Torrent::SetMetadata()
// validates `info' (piece length, name / name.utf-8, files[] with path / path.utf-8 components —
// the path checks upstream hardened in 67d5e05 — length, pieces) and Startup() builds the piece
// table and validates the first piece through MakePath()/OpenFile() under the output directory.
//
// Input: the bytes of a .torrent file, written to a fresh temporary file.
//
// The session ends once the metadata is accepted (HasMetadata(), after Startup()) or rejected
// (Done()), before any tracker or peer is contacted: the network side is not part of this target.
//
// State kept across inputs: only the ResMgr settings set once in LLVMFuzzerInitialize (metadata
// cache off, DHT off — they would write the info-hash cache under $HOME). Each input gets its own
// temporary file and output directory, removed before returning; the Torrent task is deleted,
// which unregisters it from Torrent's global table (and stops the listener with the last one).
#include "fuzz_common.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ftw.h>
#include "Torrent.h"
#include "ResMgr.h"
#include "log.h"

static const char *tmpdir()
{
   const char *t=getenv("TMPDIR");
   return t && *t ? t : "/tmp";
}

static int rm_entry(const char *p, const struct stat *, int, struct FTW *)
{
   remove(p);
   return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   if(getenv("LFTP_FUZZ_DEBUG")) {
      Log::global=new Log("debug");
      ResMgr::Set("log:level",0,"9");
      ResMgr::Set("log:enabled",0,"true");
   }
   ResMgr::Set("torrent:save-metadata",0,"no");
   ResMgr::Set("torrent:use-dht",0,"no");
   // settle the scheduler's start-up tasks before any task exists, as lftp's main() does
   SMTask::Schedule();
   Torrent::ClassInit();
   return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if(size>(1<<20))
      return -1;
   xstring file(tmpdir());
   file.append("/lftp-fuzz-XXXXXX.torrent");
   int fd=mkstemps(file.get_non_const(),8);
   if(fd<0)
      return 0;
   size_t done=0;
   while(done<size) {
      ssize_t w=write(fd,data+done,size-done);
      if(w<=0)
	 break;
      done+=w;
   }
   close(fd);
   xstring outdir(tmpdir());
   outdir.append("/lftp-fuzz-out-XXXXXX");
   if(!mkdtemp(outdir.get_non_const())) {
      unlink(file);
      return 0;
   }

   Torrent *t=new Torrent(file,outdir,outdir);
   for(int round=0; round<100000; round++) {
      SMTask::Schedule();
      if(t->Done() || t->HasMetadata())
	 break;
      SMTask::Block();
   }
   SMTask::Delete(t);
   SMTask::Schedule();

   nftw(outdir,rm_entry,16,FTW_DEPTH|FTW_PHYS);
   unlink(file);
   return 0;
}
