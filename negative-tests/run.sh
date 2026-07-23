#!/usr/bin/env bash
# Negative tests: each file under cases/ except the control MUST FAIL to
# typecheck. The control MUST compile, proving the harness can tell the
# difference. Exit 0 iff every expectation holds.
set -u
cd "$(dirname "$0")/.."
export LANG=C.UTF-8 LC_ALL=C.UTF-8

# Make the built library visible to a bare `ghc` invocation.
cabal build --write-ghc-environment-files=always lib:custodian-verified >/dev/null 2>&1

rc=0

echo "== positive control (must compile) =="
if ghc -fno-code -v0 negative-tests/cases/Control_ShouldCompile.hs 2>/dev/null; then
  echo "  control: compiled (ok)"
else
  echo "  control: FAILED TO COMPILE -- harness broken"; rc=1
fi

echo "== negative cases (each must be rejected) =="
for f in Case1_DoubleTeardown Case2_ScopeEscape Case3_LiveMapEscape Case4_BadArrayKey Case5_ArrayDelete; do
  if ghc -fno-code -v0 "negative-tests/cases/$f.hs" 2>/dev/null; then
    echo "  $f: COMPILED -- guarantee BROKEN"; rc=1
  else
    echo "  $f: rejected (ok)"
  fi
done

if [ "$rc" -eq 0 ]; then echo "ALL NEGATIVE-TEST EXPECTATIONS MET"; else echo "NEGATIVE TESTS FAILED"; fi
exit "$rc"
