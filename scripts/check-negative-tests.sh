#!/usr/bin/env bash
# Confirms negative-tests/Negative.hs fails to compile, and that it fails
# for the *right* reason (a linearity violation), not some unrelated
# error (a typo, a missing import, a stale dependency, etc.).
set -uo pipefail

OUTPUT=$(cabal build negative-tests -f negative-tests-enabled 2>&1)
STATUS=$?

if [ "$STATUS" -eq 0 ]; then
  echo "FAIL: negative-tests compiled successfully."
  echo "This means linear typing is NOT rejecting the double-teardown case -- a real regression, not a test-harness issue."
  exit 1
fi

if echo "$OUTPUT" | grep -qi "multiplicity\|used more than once\|Illegal use of linear"; then
  # Explicitly reject known false-positive shapes: a missing-extension
  # complaint also mentions "linear" (in "LinearTypes") but isn't a
  # linearity violation at all -- it means the file never even reached
  # the check we're trying to run. Caught this exact false pass earlier.
  if echo "$OUTPUT" | grep -qi "Perhaps you intended to use"; then
    echo "FAIL: negative-tests failed to compile, but due to a missing language extension, not a linearity violation. Actual output:"
    echo "$OUTPUT"
    exit 1
  fi
  echo "OK: negative-tests failed to compile with a linearity-related error, as expected."
  exit 0
else
  echo "FAIL: negative-tests failed to compile, but not with a linearity error. Actual output:"
  echo "$OUTPUT"
  exit 1
fi
