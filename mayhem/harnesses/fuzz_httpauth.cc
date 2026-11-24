// Fuzzes the HTTP WWW-Authenticate / Proxy-Authenticate challenge parser and
// the Basic/Digest response generation (src/HttpAuth.cc), as Http::HandleAuth does.
#include "fuzz_common.h"
#include "HttpAuth.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if(size>8192)
      return 0;
   xstring hdr((const char*)data,size);      // a header value is a C string in Http.cc
   static const char uri[]="http://example.com/dir/file";
   if(HttpAuth::New(HttpAuth::WWW,uri,new HttpAuth::Challenge(hdr),"user","pass")) {
      HttpAuth *auth=HttpAuth::Get(HttpAuth::WWW,uri,"user");
      if(auth) {
	 auth->Update("GET","/dir/file");
	 (void)auth->GetHeader();
      }
   }
   // drop the cached auth so the next input starts from an empty cache
   HttpAuth::CleanCache(HttpAuth::WWW,uri,"user");
   return 0;
}
