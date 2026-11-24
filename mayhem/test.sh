#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# lftp ships no offline unit suite (tests/ are live-network example programs), so the oracle is a
# set of known-answer probes driving the plain (normal-flags) lftp CLI that build.sh built, over its
# local file:// protocol: each asserts exact output/side effects, so a neutered lftp fails them all.
LFTP="$SRC/mayhem/build-test/src/lftp"
passed=0; failed=0
if [ ! -x "$LFTP" ]; then
  echo "FAIL: $LFTP missing — mayhem/build.sh must build it" >&2
  emit_ctrf "lftp-kat" 0 1 0; exit 1
fi
W=$(mktemp -d "${TMPDIR:-/tmp}/lftp-test.XXXXXX")
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/home" "$W/src/sub"
printf 'hello lftp\n' > "$W/src/a.txt"
printf 'second file\n' > "$W/src/b.txt"
printf 'nested\n' > "$W/src/sub/c.txt"
run() { HOME="$W/home" "$LFTP" --norc -c "$1" 2>&1; }
check() {  # check <name> <expected> <actual>
  if [ "$2" == "$3" ]; then passed=$((passed+1)); echo "PASS: $1"
  else failed=$((failed+1)); echo "FAIL: $1"; echo "  expected: $(printf %q "$2")"; echo "  actual:   $(printf %q "$3")"; fi
}
check "cls -1 lists the directory" $'a.txt\nb.txt\nsub/' "$(run "open file://$W/src; cls -1")"
check "cat prints a file" "hello lftp" "$(run "open file://$W/src; cat a.txt")"
check "glob expands a pattern" "a.txt b.txt" "$(run "open file://$W/src; glob echo *.txt")"
run "open file://$W/src; get b.txt -o $W/got.txt" >/dev/null
check "get copies file content" "second file" "$(cat "$W/got.txt" 2>/dev/null)"
run "mirror file://$W/src $W/mirror" >/dev/null
check "mirror copies the tree" "$(cd "$W/src" && find . -type f | sort | xargs cat)" \
      "$(cd "$W/mirror" 2>/dev/null && find . -type f | sort | xargs cat)"
check "cls -s reports sizes" "11 a.txt" "$(run "open file://$W/src; cls --block-size=1 -s a.txt" | tr -s ' ' | sed 's/^ //')"
emit_ctrf "lftp-kat" "$passed" "$failed" 0
