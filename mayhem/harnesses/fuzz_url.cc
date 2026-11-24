// Fuzzes URL parsing/recombination (src/url.cc): ParsedURL, CombineTo and the
// percent decoder, in both rfc1738 and non-rfc1738 modes.
#include "fuzz_common.h"
#include "url.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if(size<1 || size>4096)
      return 0;
   bool rfc1738=data[0]&1;
   bool proto_required=data[0]&2;
   xstring s((const char*)data+1,size-1);   // NUL-terminated copy
   ParsedURL u(s,proto_required,rfc1738);
   xstring out;
   u.CombineTo(out,"/home",rfc1738);
   (void)url::decode(s);
   (void)url::path_ptr(s);
   (void)url::is_url(s);
   return 0;
}
