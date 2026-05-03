#!/bin/bash
###############################################################################
# tests/run-tests.sh — Smoke tests for Preston-Check lib/ modules
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export ROOT

PASS=0
FAIL=0
FAIL_NAMES=()

assert() {
  local description="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    PASS=$((PASS+1))
    echo "  PASS: $description"
  else
    FAIL=$((FAIL+1))
    FAIL_NAMES+=("$description")
    echo "  FAIL: $description"
    echo "    expected: $expected"
    echo "    actual:   $actual"
  fi
}

assert_contains() {
  local description="$1"
  local haystack="$2"
  local needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS+1))
    echo "  PASS: $description"
  else
    FAIL=$((FAIL+1))
    FAIL_NAMES+=("$description")
    echo "  FAIL: $description"
  fi
}

assert_true() {
  local description="$1"
  if [[ "$2" == "true" || "$2" == "0" ]]; then
    PASS=$((PASS+1))
    echo "  PASS: $description"
  else
    FAIL=$((FAIL+1))
    FAIL_NAMES+=("$description")
    echo "  FAIL: $description"
  fi
}

echo ""
echo "============================================================================"
echo "  Preston-Check test suite"
echo "============================================================================"
echo ""

for test_file in "$SCRIPT_DIR/lib"/*.sh; do
  [[ -f "$test_file" ]] || continue
  echo "Running $(basename "$test_file")..."
  source "$test_file"
  echo ""
done

echo "============================================================================"
echo "  Summary"
echo "============================================================================"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "Failed tests:"
  for n in "${FAIL_NAMES[@]}"; do echo "  - $n"; done
  exit 1
fi
echo ""
exit 0
