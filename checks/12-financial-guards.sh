#!/bin/bash
# P-12: Financial transaction guards
# Money-managing systems must have balance checks, double-spend prevention,
# amount validation, and reconciliation mechanisms.

echo "P-12: Financial Guards"

SRC="${SOURCE_DIR:-.}"

# Check for balance validation before withdrawals
balance_check=$(grep -rn --include="*.java" \
  --max-count=10 "balance.*sufficient\|isBalanceAvailable\|checkBalance\|getBalance.*compare\|qty.*compare" \
  "$SRC" 2>/dev/null \
  | grep -i "withdraw\|transfer\|funds_out\|pay\|send" \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$balance_check" ]]; then
  count=$(echo "$balance_check" | wc -l)
  record "PASS" "P-12 Balance validation" "$count balance check patterns in financial paths"
else
  record "FAIL" "P-12 Balance validation" "No balance validation found before withdrawals"
fi

# Check for negative amount validation
negative_check=$(grep -rn --include="*.java" \
  --max-count=10 "amount.*<= 0\|amount.*compareTo.*ZERO\|amount.*negative\|validateAmount\|BigDecimal.ZERO.*compare" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$negative_check" ]]; then
  record "PASS" "P-12 Negative amount check" "Amount validation found"
else
  record "WARN" "P-12 Negative amount check" "No explicit negative/zero amount validation found"
fi

# Check for FOR UPDATE locking on financial queries
for_update=$(grep -rn --include="*.java" \
  --max-count=10 "FOR UPDATE\|pessimistic\|PESSIMISTIC_WRITE\|advisory_lock\|pg_try_advisory" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -10)

if [[ -n "$for_update" ]]; then
  count=$(echo "$for_update" | wc -l)
  record "PASS" "P-12 Row locking" "$count row-locking patterns for financial operations"
else
  record "FAIL" "P-12 Row locking" "No FOR UPDATE or advisory lock patterns found"
fi

# Check for transaction ID generation (collision resistance)
txn_id=$(grep -rn --include="*.java" \
  --max-count=5 "generateTransactionId\|UUID.randomUUID\|SecureRandom.*transaction" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$txn_id" ]]; then
  record "PASS" "P-12 Transaction IDs" "Collision-resistant transaction ID generation found"
else
  record "WARN" "P-12 Transaction IDs" "No secure transaction ID generation pattern found"
fi
