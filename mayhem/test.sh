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

# Upstream's C++ QA suite (Boost.Test binaries built by build.sh into build-tests/: runtime,
# math, PMT, blocks, fft, filter and digital header parsers). Each binary is run directly with a
# Boost.Test XML report; counts are its test cases. A binary that writes no report or does not
# report "passed" fails (so a neutered program cannot pass).
BT="$SRC/build-tests"
[ -f "$BT/CTestTestfile.cmake" ] || { echo "build-tests/ missing: run mayhem/build.sh first" >&2; emit_ctrf boost-test 0 1; exit 1; }
mapfile -t bins < <(find "$BT" -type f -perm -u+x \( -name '*_qa_*.cc' -o -name 'pmt_prims' -o -name 'pmt_unv' \) | sort)
[ "${#bins[@]}" -gt 0 ] || { echo "no QA binaries under build-tests/" >&2; emit_ctrf boost-test 0 1; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# GNU Radio writes its prefs (vmcircbuf choice) under the user config dir; keep it private.
export GR_PREFS_PATH="$work/prefs" GR_CACHE_PATH="$work/cache" HOME="$work"
mkdir -p "$GR_PREFS_PATH" "$GR_CACHE_PATH"

passed=0; failed=0; skipped=0
for b in "${bins[@]}"; do
  name="$(basename "$b")"
  rep="$work/$name.xml"
  (cd "$(dirname "$b")" && "$b" --log_level=nothing --report_level=detailed \
     --report_format=XML --report_sink="$rep") > "$work/$name.log" 2>&1
  rc=$?
  read -r p f s ok < <(python3 -I - "$rep" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
    suite = root if root.tag == "TestSuite" else root.find("TestSuite")
    a = suite.attrib
    p = int(a.get("test_cases_passed", 0)); f = int(a.get("test_cases_failed", 0)) + int(a.get("test_cases_aborted", 0))
    s = int(a.get("test_cases_skipped", 0))
    ok = 1 if a.get("result") == "passed" and p > 0 and int(a.get("assertions_passed", 0)) > 0 else 0
    print(p, f, s, ok)
except Exception:
    print(0, 0, 0, 0)
PY
)
  if [ "$rc" -ne 0 ] || [ "$ok" -ne 1 ]; then
    echo "FAIL: $name (exit $rc)"; tail -20 "$work/$name.log"
    [ "$f" -gt 0 ] || f=1
  else
    echo "ok:   $name ($p cases)"
  fi
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + s))
done
emit_ctrf boost-test "$passed" "$failed" "$skipped"
