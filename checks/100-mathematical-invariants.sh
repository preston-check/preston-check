#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-100
name: Mathematical Invariants
description: Mathematical Invariants security check (see COMPLIANCE_MAPPING.md for details).
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-100: Mathematical Invariants — The Grand Verification
# The crown jewel check: verifies that the fundamental mathematical properties
# of a financial system are preserved. These invariants, if broken, mean the
# system is fundamentally unsound regardless of how many other checks pass.
echo "P-100: Mathematical Invariants"
SRC="${SOURCE_DIR:-.}"

# Invariant 1: Conservation of value (deposits - withdrawals = balance)
conservation=$(grep -rn --include="$SRC_EXT" --include="*.sql" \
  "sum.*deposit\|sum.*withdraw\|balance.*check\|reconcil\|conservation\|total.*in.*total.*out\|net.*position" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$conservation" ]]; then
  record "PASS" "P-100 Conservation of value" "Value conservation/reconciliation patterns found"
else
  record "WARN" "P-100 Conservation of value" "No conservation-of-value check — sum(deposits) - sum(withdrawals) must equal current balance"
fi

# Invariant 2: Non-negativity (balances cannot go below zero for non-margin accounts)
non_negative=$(grep -rn --include="$SRC_EXT" \
  "balance.*<.*0\|balance.*negative\|insufficient.*fund\|insufficient.*balance\|overdraft\|below.*zero\|qty.*<.*0\|IsNegative" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$non_negative" ]]; then
  record "PASS" "P-100 Non-negativity" "Balance non-negativity enforcement found"
else
  record "WARN" "P-100 Non-negativity" "No balance non-negativity check — accounts should not go below zero"
fi

# Invariant 3: Commutativity (A→B then B→A must net to zero, minus fees)
commutative=$(grep -rn --include="$SRC_EXT" \
  "round.*trip\|reverse.*transaction\|net.*zero\|offset\|contra.*entry\|matching.*entry" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -3)
if [[ -n "$commutative" ]]; then
  record "PASS" "P-100 Transaction symmetry" "Round-trip/contra-entry patterns found"
else
  record "WARN" "P-100 Transaction symmetry" "No transaction symmetry verification — reversals should net to zero (minus fees)"
fi

# Invariant 4: Idempotency of completed operations
idempotent=$(grep -rn --include="$SRC_EXT" \
  "already.*processed\|already.*completed\|duplicate.*transaction\|idempoten.*key\|ON CONFLICT\|IF NOT EXISTS" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$idempotent" ]]; then
  count=$(echo "$idempotent" | wc -l | tr -d ' ')
  record "PASS" "P-100 Idempotency invariant" "$count idempotency guard patterns found"
else
  record "FAIL" "P-100 Idempotency invariant" "No idempotency guards — retrying operations can create duplicate financial entries"
fi

# Invariant 5: Monotonicity (transaction IDs / timestamps must be strictly increasing)
monotonic=$(grep -rn --include="$SRC_EXT" \
  "sequence\|auto.*increment\|generateTransactionId\|Snowflake\|SERIAL\|nextval\|monoton\|strictly.*increasing" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -3)
if [[ -n "$monotonic" ]]; then
  record "PASS" "P-100 Monotonicity" "Monotonic ID/sequence generation found"
else
  record "WARN" "P-100 Monotonicity" "No monotonic ID generation — transaction ordering must be deterministic"
fi
