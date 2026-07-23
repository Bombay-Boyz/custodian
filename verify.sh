#!/usr/bin/env bash
# One command that runs everything: builds the library under -Wall -Werror,
# runs the Hedgehog property/unit suite, runs the compile-must-fail negative
# tests, and compiles the real libbpf backend (no link/run -- needs a kernel).
set -u
cd "$(dirname "$0")"
export PATH="$HOME/.ghcup/bin:$PATH"
export LANG=C.UTF-8 LC_ALL=C.UTF-8
rc=0

echo "############ 1. library (-Wall -Werror) ############"
cabal build lib:custodian-verified || rc=1

echo "############ 2. property + unit tests (Hedgehog) ############"
cabal test verified-test --test-show-details=streaming || rc=1

echo "############ 3. negative (compile-must-fail) tests ############"
bash negative-tests/run.sh || rc=1

FILES=$(find src test -name '*.hs')

echo "############ 4. HLint (incl. no-partial-functions rule) ############"
if command -v hlint >/dev/null 2>&1; then
  hlint --hint=.hlint.yaml $FILES || rc=1
else
  echo "  hlint not on PATH -- runs in CI (.github/workflows/ci.yml)"
fi

echo "############ 5. Fourmolu (format check) ############"
if command -v fourmolu >/dev/null 2>&1; then
  fourmolu --mode check $FILES || rc=1
else
  echo "  fourmolu not on PATH -- runs in CI (.github/workflows/ci.yml)"
fi

echo "############ 6. live package: build + link libbpf, run (skips w/o kernel) ############"
if [ -f /usr/include/bpf/libbpf.h ] && ldconfig -p 2>/dev/null | grep -q libbpf; then
  cabal build custodian-live:custodian-syscall-counter custodian-live:live-spec || rc=1
  EXE=$(find dist-newstyle -type f -name custodian-syscall-counter 2>/dev/null | head -1)
  LSPEC=$(find dist-newstyle -type f -name live-spec 2>/dev/null | head -1)
  [ -n "$EXE" ] && echo "  example runs:" && "$EXE"
  [ -n "$LSPEC" ] && echo "  live-spec runs:" && "$LSPEC"
else
  echo "  skipped: libbpf not installed (apt-get install libbpf-dev)"
fi

echo
if [ "$rc" -eq 0 ]; then echo "==== ALL CHECKS PASSED ===="; else echo "==== SOME CHECKS FAILED ===="; fi
exit "$rc"
