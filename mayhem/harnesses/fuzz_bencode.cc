// Fuzzes the bencode decoder (src/Bencode.cc) used for .torrent files, tracker
// replies, DHT and peer extension messages; re-encodes and pretty-prints the tree.
#include "fuzz_common.h"
#include "Bencode.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   if(size>(1<<20))
      return 0;
   int rest=0;
   BeNode *node=BeNode::Parse((const char*)data,(int)size,&rest);
   if(node) {
      xstring out;
      node->Pack(out);
      xstring fmt;
      node->Format(fmt,0);
      (void)node->Format1();
      delete node;
   }
   return 0;
}
