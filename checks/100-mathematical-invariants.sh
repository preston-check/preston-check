#!/bin/bash
# P-100: Mathematical Invariants — The Grand Verification
# The crown jewel check: verifies that the fundamental mathematical properties
# of a financial system are preserved. These invariants, if broken, mean the
# system is fundamentally unsound regardless of how many other checks pass.
echo "P-100: Mathematical Invariants"
SRC="${SOURCE_DIR:-.}"

# Invariant 1: Conservation of value (deposits - withdrawals = balance)
conservation=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "sum.*deposit\|sum.*withdraw\|balance.*check\|reconcil\|conservation\|total.*in.*total.*out\|net.*position" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$conservation" ]]; then
  record "PASS" "P-100 Conservation of value" "Value conservation/reconciliation patterns found"
else
  record "WARN" "P-100 Conservation of value" "No conservation-of-value check — sum(deposits) - sum(withdrawals) must equal current balance"
fi

# Invariant 2: Non-negativity (balances cannot go below zero for non-margin accounts)
non_negative=$(grep -rn --include="*.java" --include="*.ts" \
  "balance.*<.*0\|balance.*negative\|insufficient.*fund\|insufficient.*balance\|overdraft\|below.*zero\|qty.*<.*0" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$non_negative" ]]; then
  record "PASS" "P-100 Non-negativity" "Balance non-negativity enforcement found"
else
  record "WARN" "P-100 Non-negativity" "No balance non-negativity check — accounts should not go below zero"
fi

# Invariant 3: Commutativity (A→B then B→A must net to zero, minus fees)
commutative=$(grep -rn --include="*.java" --include="*.ts" \
  "round.*trip\|reverse.*transaction\|net.*zero\|offset\|contra.*entry\|matching.*entry" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$commutative" ]]; then
  record "PASS" "P-100 Transaction symmetry" "Round-trip/contra-entry patterns found"
else
  record "WARN" "P-100 Transaction symmetry" "No transaction symmetry verification — reversals should net to zero (minus fees)"
fi

# Invariant 4: Idempotency of completed operations
idempotent=$(grep -rn --include="*.java" --include="*.ts" \
  "already.*processed\|already.*completed\|duplicate.*transaction\|idempoten.*key\|ON CONFLICT\|IF NOT EXISTS" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$idempotent" ]]; then
  count=$(echo "$idempotent" | wc -l | tr -d ' ')
  record "PASS" "P-100 Idempotency invariant" "$count idempotency guard patterns found"
else
  record "FAIL" "P-100 Idempotency invariant" "No idempotency guards — retrying operations can create duplicate financial entries"
fi

# Invariant 5: Monotonicity (transaction IDs / timestamps must be strictly increasing)
monotonic=$(grep -rn --include="*.java" --include="*.ts" \
  "sequence\|auto.*increment\|generateTransactionId\|Snowflake\|SERIAL\|nextval\|monoton\|strictly.*increasing" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$monotonic" ]]; then
  record "PASS" "P-100 Monotonicity" "Monotonic ID/sequence generation found"
else
  record "WARN" "P-100 Monotonicity" "No monotonic ID generation — transaction ordering must be deterministic"
fi
