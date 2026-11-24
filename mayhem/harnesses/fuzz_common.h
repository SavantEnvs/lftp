// Shared prolog for the lftp fuzz harnesses (mayhem/harnesses/*.cc).
#ifndef LFTP_FUZZ_COMMON_H
#define LFTP_FUZZ_COMMON_H
#include <config.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "xstring.h"
// lftp's libraries reference the program name set by main() in src/lftp.cc.
char *program_name=(char*)"lftp-fuzz";
#endif
