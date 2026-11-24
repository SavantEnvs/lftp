// Fuzzes the fish directory-listing parser through the session's public
// FileAccess::ParseLongList() (the same call the "cls"/"ls" machinery uses on
// the bytes a remote server sends back).
#include "fuzz_common.h"
#include "FileAccess.h"
#include "FileSet.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   static FileAccess *session=FileAccess::New("fish","example.com");
   if(!session || size>(1<<20))
      return 0;
   int err=0;
   // lftp hands this parser the contents of its I/O Buffer, which (an xstring) is always
   // NUL-terminated past len; the parsers rely on that, so pass the same shape.
   xstring buf((const char*)data,size);
   FileSet *set=session->ParseLongList(buf.get(),(int)size,&err);
   if(set) {
      set->Sort(FileSet::BYNAME,false);
      set->ExcludeDots();
      int d,f,s,o; set->Count(&d,&f,&s,&o);
      for(FileInfo *fi=set->curr(); fi; fi=set->next())
	 (void)fi->GetLongName();
      delete set;
   }
   return 0;
}
