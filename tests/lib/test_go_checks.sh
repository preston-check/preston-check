###############################################################################
# tests/lib/test_go_checks.sh — Behavioral tests for Go check blocks
#
# Relies on assert_warns/assert_passes from _check_harness.sh (loaded first).
# Covers both the dedicated Go checks (490–495) and the Go blocks added to
# general checks (P-17, P-52, P-494).
###############################################################################

echo "--- Go check tests ---"

CHECKS="$ROOT/checks"
# Fixtures live in testdata/ (not tests/fixtures/) to avoid the /tests?/ exclusion
# filter that the check scripts use when scanning for non-test code.
GO_BAD="$ROOT/testdata/go-bad"
GO_CLEAN="$ROOT/testdata/go-clean"

# ---------------------------------------------------------------------------
# P-17: Secure randomness
# ---------------------------------------------------------------------------
assert_warns "P-17 Go: math/rand triggers WARN" \
  "$CHECKS/17-secure-random.sh" "$GO_BAD" "Secure randomness (Go)"

assert_passes "P-17 Go: crypto/rand passes" \
  "$CHECKS/17-secure-random.sh" "$GO_CLEAN" "Secure randomness (Go)"

# ---------------------------------------------------------------------------
# P-52: Timing-safe comparison
# ---------------------------------------------------------------------------
assert_warns "P-52 Go: no subtle.ConstantTimeCompare triggers WARN" \
  "$CHECKS/52-timing-attacks.sh" "$GO_BAD" "Timing-Safe Comparison (Go)"

assert_passes "P-52 Go: subtle.ConstantTimeCompare present — PASS" \
  "$CHECKS/52-timing-attacks.sh" "$GO_CLEAN" "Timing-Safe Comparison (Go)"

# ---------------------------------------------------------------------------
# P-490: Ignored errors (_, _ = pattern)
# ---------------------------------------------------------------------------
assert_warns "P-490 Go: _, _ = triggers WARN" \
  "$CHECKS/490-go-ignored-errors.sh" "$GO_BAD"

assert_passes "P-490 Go: all errors checked — PASS" \
  "$CHECKS/490-go-ignored-errors.sh" "$GO_CLEAN"

# ---------------------------------------------------------------------------
# P-491: float64/float32 for monetary fields (check always returns FAIL, not WARN)
# ---------------------------------------------------------------------------
assert_fails "P-491 Go: amount/price float64 triggers FAIL" \
  "$CHECKS/491-go-float-money.sh" "$GO_BAD"

assert_passes "P-491 Go: decimal.Decimal for money — PASS" \
  "$CHECKS/491-go-float-money.sh" "$GO_CLEAN"

# ---------------------------------------------------------------------------
# P-492: Race conditions (goroutines without mutex)
# ---------------------------------------------------------------------------
assert_warns "P-492 Go: goroutines without sync primitive triggers WARN" \
  "$CHECKS/492-go-race-conditions.sh" "$GO_BAD"

assert_passes "P-492 Go: goroutines guarded by sync.Mutex — PASS" \
  "$CHECKS/492-go-race-conditions.sh" "$GO_CLEAN"

# ---------------------------------------------------------------------------
# P-493: Non-constant-time comparison (check returns FAIL when == found without subtle)
# ---------------------------------------------------------------------------
assert_fails "P-493 Go: token == without subtle triggers FAIL" \
  "$CHECKS/493-go-constant-time-compare.sh" "$GO_BAD"

assert_passes "P-493 Go: no == on token/secret — PASS" \
  "$CHECKS/493-go-constant-time-compare.sh" "$GO_CLEAN"

# ---------------------------------------------------------------------------
# P-494: HTTP/DB calls without context.Context
# ---------------------------------------------------------------------------
assert_warns "P-494 Go: bare http.Get() without context triggers WARN" \
  "$CHECKS/494-go-context-cancellation.sh" "$GO_BAD"

assert_passes "P-494 Go: context-aware client.Do and QueryRowContext — PASS" \
  "$CHECKS/494-go-context-cancellation.sh" "$GO_CLEAN"

# ---------------------------------------------------------------------------
# P-495: SQL injection via fmt.Sprintf in QueryContext (check returns FAIL, not WARN)
# ---------------------------------------------------------------------------
assert_fails "P-495 Go: fmt.Sprintf in QueryContext triggers FAIL" \
  "$CHECKS/495-go-sql-injection.sh" "$GO_BAD"

assert_passes "P-495 Go: parameterized query with placeholder — PASS" \
  "$CHECKS/495-go-sql-injection.sh" "$GO_CLEAN"
