#!/usr/bin/env bash
# Confirms negative-tests/Negative.hs fails to compile, and that it fails
# for the *right* reasons: a linearity violation (badDoubleTeardown) AND
# a rank-2 scope-escape violation (badMapEscape) -- not some unrelated
# error (a typo, a missing import, a stale dependency, etc.) that would
# make the file fail for the wrong reason while looking superficially OK.
set -uo pipefail

OUTPUT=$(cabal build negative-tests -f negative-tests-enabled 2>&1)
STATUS=$?

if [ "$STATUS" -eq 0 ]; then
  echo "FAIL: negative-tests compiled successfully."
  echo "This means linear typing and/or rank-2 scoping is NOT rejecting one of the bad cases -- a real regression, not a test-harness issue."
  exit 1
fi

if echo "$OUTPUT" | grep -qi "Perhaps you intended to use"; then
  echo "FAIL: negative-tests failed to compile, but due to a missing language extension, not the violations under test. Actual output:"
  echo "$OUTPUT"
  exit 1
fi

FOUND_LINEARITY=0
FOUND_ESCAPE=0

if echo "$OUTPUT" | grep -qi "multiplicity\|used more than once\|Illegal use of linear"; then
  FOUND_LINEARITY=1
fi

if echo "$OUTPUT" | grep -qi "would escape\|escape its scope\|escape from its scope\|skolem"; then
  FOUND_ESCAPE=1
fi

if [ "$FOUND_LINEARITY" -eq 1 ] && [ "$FOUND_ESCAPE" -eq 1 ]; then
  echo "OK: both badDoubleTeardown (linearity) and badMapEscape (rank-2 scope escape) failed to compile for the expected reasons."
  exit 0
else
  echo "FAIL: negative-tests failed to compile, but not both expected violations were found."
  echo "Linearity error found: $FOUND_LINEARITY"
  echo "Escape error found:    $FOUND_ESCAPE"
  echo "Actual output:"
  echo "$OUTPUT"
  exit 1
fi
