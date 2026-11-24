#!/usr/bin/env bash
#
# mayhem/build.sh — build lftp's fuzz harnesses (sanitized) and a plain lftp for mayhem/test.sh.
#
# lftp is autotools + gnulib: autogen.sh runs gnulib-tool (from the Debian `gnulib` package in the
# image, so this is offline) and generates ./configure. Both builds are out of tree under mayhem/
# (gitignored by mayhem/.gitignore):
#   mayhem/build-fuzz  ASan+UBSan + SanCov (fuzzer-no-link), DWARF 3 — linked into the harnesses
#   mayhem/build-test  the project's normal flags — the src/lftp CLI that mayhem/test.sh drives
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

CONF_ARGS=(--disable-shared --enable-static --without-gnutls --with-openssl --disable-nls
           --without-libidn2 --without-libresolv)

# 0) generate ./configure (only when missing — e.g. after `git clean -ffdX`). gnulib-tool --update
#    rewrites two tracked m4 files with its own normalisation; put them back so the tree stays clean.
if [ ! -x configure ]; then
  cp m4/.gitignore /tmp/lftp-m4-gitignore.$$ ; cp m4/gnulib-cache.m4 /tmp/lftp-m4-cache.$$
  NOCONFIGURE=1 ./autogen.sh
  cp /tmp/lftp-m4-gitignore.$$ m4/.gitignore ; cp /tmp/lftp-m4-cache.$$ m4/gnulib-cache.m4
  rm -f /tmp/lftp-m4-gitignore.$$ /tmp/lftp-m4-cache.$$
fi

# 1) sanitized + coverage-instrumented library build (the fuzzed code itself)
# UBSan nonnull-attribute is relaxed: lftp calls memcpy(dst,NULL,0) through xstring::set_substr(…,0,0)
# (e.g. HttpDir.cc parse_html stripping a slash) on ordinary listings, which would halt every run.
# ASan and the rest of UBSan stay on and halting.
UBSAN_RELAX="-fno-sanitize=nonnull-attribute"
FUZZ_CFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
mkdir -p mayhem/build-fuzz
( cd mayhem/build-fuzz
  [ -f config.status ] || ../../configure "${CONF_ARGS[@]}" CC="$CC" CXX="$CXX" \
      CFLAGS="$FUZZ_CFLAGS" CXXFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS"
  make -j"$MAYHEM_JOBS" )

B=mayhem/build-fuzz
LIBS=(-Wl,--start-group "$B"/src/.libs/*.a "$B"/lib/.libs/libgnu.a -Wl,--end-group
      -lssl -lcrypto -lz -lexpat -lreadline -lncurses -lutil -ldl -lresolv -lpthread)
INC=(-DHAVE_CONFIG_H -I"$B"/lib -Ilib -I"$B" -Isrc -Itrio -I"$B"/src)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B"/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$B"/standalone_main.o

# 2) one libFuzzer binary + one run-once reproducer per harness
for h in mayhem/harnesses/fuzz_*.cc; do
  n=$(basename "$h" .cc)
  $CXX $SANITIZER_FLAGS $UBSAN_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -fno-rtti -fno-exceptions "${INC[@]}" -c "$h" -o "$B/$n.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$n.o" "$B"/lsan_off.o "${LIBS[@]}" \
      -o "/mayhem/$n"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$n.o" "$B"/standalone_main.o "$B"/lsan_off.o "${LIBS[@]}" \
      -o "/mayhem/$n-standalone"
done

# 3) plain lftp (normal flags) for the functional oracle in mayhem/test.sh
mkdir -p mayhem/build-test
( cd mayhem/build-test
  [ -f config.status ] || env -u CFLAGS -u CXXFLAGS -u LDFLAGS ../../configure "${CONF_ARGS[@]}" \
      CC="$CC" CXX="$CXX" CFLAGS="-O2 $COVERAGE_FLAGS" CXXFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  make -j"$MAYHEM_JOBS" )
test -x mayhem/build-test/src/lftp
