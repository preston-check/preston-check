###############################################################################
# tests/lib/test_rust_checks.sh — Behavioral tests for Rust check blocks
#
# Relies on assert_warns/assert_passes from _check_harness.sh (loaded first).
# Covers both the dedicated Rust checks (500–505) and the Rust blocks added
# to general checks (P-17, P-52).
###############################################################################

echo "--- Rust check tests ---"

CHECKS="$ROOT/checks"
# Fixtures live in testdata/ (not tests/fixtures/) to avoid the /tests?/ exclusion
# filter that the check scripts use when scanning for non-test code.
RS_BAD="$ROOT/testdata/rust-bad"
RS_CLEAN="$ROOT/testdata/rust-clean"

# ---------------------------------------------------------------------------
# P-17: Secure randomness
# ---------------------------------------------------------------------------
assert_warns "P-17 Rust: thread_rng triggers WARN" \
  "$CHECKS/17-secure-random.sh" "$RS_BAD" "Secure randomness (Rust)"

assert_passes "P-17 Rust: OsRng — no insecure PRNG — PASS" \
  "$CHECKS/17-secure-random.sh" "$RS_CLEAN" "Secure randomness (Rust)"

# ---------------------------------------------------------------------------
# P-52: Timing-safe comparison
# ---------------------------------------------------------------------------
assert_warns "P-52 Rust: no ct_eq/subtle triggers WARN" \
  "$CHECKS/52-timing-attacks.sh" "$RS_BAD" "Timing-Safe Comparison (Rust)"

assert_passes "P-52 Rust: ct_eq (subtle::ConstantTimeEq) present — PASS" \
  "$CHECKS/52-timing-attacks.sh" "$RS_CLEAN" "Timing-Safe Comparison (Rust)"

# ---------------------------------------------------------------------------
# P-500: unwrap()/expect() in production code
# ---------------------------------------------------------------------------
assert_warns "P-500 Rust: .unwrap()/.expect() triggers WARN" \
  "$CHECKS/500-rust-unwrap-production.sh" "$RS_BAD"

assert_passes "P-500 Rust: Result propagation with ? — no unwrap — PASS" \
  "$CHECKS/500-rust-unwrap-production.sh" "$RS_CLEAN"

# ---------------------------------------------------------------------------
# P-501: Integer overflow on financial fields
# ---------------------------------------------------------------------------
assert_warns "P-501 Rust: amount * raw arithmetic triggers WARN" \
  "$CHECKS/501-rust-integer-overflow.sh" "$RS_BAD"

assert_passes "P-501 Rust: checked_mul/checked_add — no raw arithmetic — PASS" \
  "$CHECKS/501-rust-integer-overflow.sh" "$RS_CLEAN"

# ---------------------------------------------------------------------------
# P-502: unsafe blocks
# ---------------------------------------------------------------------------
assert_warns "P-502 Rust: unsafe { } block triggers WARN" \
  "$CHECKS/502-rust-unsafe-blocks.sh" "$RS_BAD"

assert_passes "P-502 Rust: no unsafe blocks — PASS" \
  "$CHECKS/502-rust-unsafe-blocks.sh" "$RS_CLEAN"

# ---------------------------------------------------------------------------
# P-503: Weak crypto crates — check always returns FAIL (not WARN)
# ---------------------------------------------------------------------------
assert_fails "P-503 Rust: use md5 triggers FAIL" \
  "$CHECKS/503-rust-weak-crypto-crates.sh" "$RS_BAD"

assert_passes "P-503 Rust: sha2 — no weak crypto crate — PASS" \
  "$CHECKS/503-rust-weak-crypto-crates.sh" "$RS_CLEAN"

# ---------------------------------------------------------------------------
# P-504: Unverified deserialization (no size/depth limits)
# ---------------------------------------------------------------------------
assert_warns "P-504 Rust: serde_json::from_slice without size limits triggers WARN" \
  "$CHECKS/504-rust-unverified-deserialize.sh" "$RS_BAD"

assert_passes "P-504 Rust: from_slice with MAX_SIZE limit present — PASS" \
  "$CHECKS/504-rust-unverified-deserialize.sh" "$RS_CLEAN"

# ---------------------------------------------------------------------------
# P-505: Insecure random for security tokens
# ---------------------------------------------------------------------------
assert_warns "P-505 Rust: session_id generated with thread_rng triggers WARN" \
  "$CHECKS/505-rust-insecure-random.sh" "$RS_BAD"

assert_passes "P-505 Rust: OsRng for session ID generation — PASS" \
  "$CHECKS/505-rust-insecure-random.sh" "$RS_CLEAN"
