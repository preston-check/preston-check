###############################################################################
# tests/lib/_check_harness.sh — Behavioral check runner for Go/Rust fixture tests
#
# Loaded first (underscore sorts before 'a') so run_check_output and the
# assert_warns/assert_passes/assert_skips helpers are available to all test
# files that follow.
#
# Usage:
#   assert_warns  "description" "$CHECKS/NNN-name.sh" "$FIXTURES/go-bad"  ["label pattern"]
#   assert_passes "description" "$CHECKS/NNN-name.sh" "$FIXTURES/go-clean" ["label pattern"]
#   assert_skips  "description" "$CHECKS/NNN-name.sh" "$FIXTURES/empty"    ["label pattern"]
###############################################################################

# run_check_output <check_file> <fixture_dir>
#
# Runs the check in an isolated bash subshell with record() replaced by a
# printer that emits "RESULT:STATUS:LABEL" lines. Errors and echo output from
# the check go to /dev/null so they don't pollute the capture.
run_check_output() {
  local check_file="$1"
  local fixture_dir="$2"
  _HARNESS_FIXTURE="$fixture_dir" _HARNESS_CHECK="$check_file" \
  bash --noprofile --norc <<'SUBSHELL' 2>/dev/null
    # Bypass any grep shell-function wrappers (e.g. ugrep shim) so the checks
    # see the real /usr/bin/grep with full ERE support.
    unset -f grep 2>/dev/null || true
    record() { printf 'RESULT:%s:%s\n' "$1" "$2"; }
    PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; SKIP_COUNT=0
    VERBOSE=false
    GREEN=''; RED=''; YELLOW=''; BLUE=''; NC=''
    SOURCE_DIR="$_HARNESS_FIXTURE"
    source "$_HARNESS_CHECK"
SUBSHELL
}

# assert_check <description> <check_file> <fixture_dir> <expected_status> [label_grep]
#
# Runs the check against the fixture dir and asserts that at least one
# record() call matched the expected STATUS and (optionally) a case-insensitive
# pattern on the LABEL string.
assert_check() {
  local desc="$1"
  local check_file="$2"
  local fixture_dir="$3"
  local expected_status="$4"
  local label_grep="${5:-}"

  local output result_lines found=0
  output=$(run_check_output "$check_file" "$fixture_dir")
  result_lines=$(printf '%s\n' "$output" | grep "^RESULT:" || true)

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local status="${line#RESULT:}"
    status="${status%%:*}"
    local label="${line#RESULT:${status}:}"
    if [[ "$status" == "$expected_status" ]]; then
      if [[ -z "$label_grep" ]] || echo "$label" | grep -qi "$label_grep"; then
        found=1
        break
      fi
    fi
  done <<< "$result_lines"

  if [[ $found -eq 1 ]]; then
    PASS=$((PASS+1))
    echo "  PASS: $desc"
  else
    FAIL=$((FAIL+1))
    FAIL_NAMES+=("$desc")
    echo "  FAIL: $desc"
    echo "    Expected: ${expected_status} matching '${label_grep:-<any>}'"
    if [[ -n "$result_lines" ]]; then
      echo "    Got:"
      printf '%s\n' "$result_lines" | sed 's/^/      /'
    else
      echo "    Got: (no RESULT lines — check may have exited early or errored)"
      printf '%s\n' "$output" | head -8 | sed 's/^/      [stdout] /'
    fi
  fi
}

assert_warns()  { assert_check "$1" "$2" "$3" "WARN" "${4:-}"; }
assert_passes() { assert_check "$1" "$2" "$3" "PASS" "${4:-}"; }
assert_skips()  { assert_check "$1" "$2" "$3" "SKIP" "${4:-}"; }
assert_fails()  { assert_check "$1" "$2" "$3" "FAIL" "${4:-}"; }
