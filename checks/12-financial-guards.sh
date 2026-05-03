#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-12
name: Financial Guards
description: Checks for balance validation, locking, negative amount protection.
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
frameworks: PCI-DSS:4.0:6.2.4, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, CIS-v8:16.1
PRESTON_META

# P-12: Financial transaction guards
# Money-managing systems must have balance checks, double-spend prevention,
# amount validation, and reconciliation mechanisms.

echo "P-12: Financial Guards"

SRC="${SOURCE_DIR:-.}"

# Check for balance validation before withdrawals
balance_check=$(grep -rn --include="$SRC_EXT" \
  "balance.*sufficient\|isBalanceAvailable\|checkBalance\|getBalance.*compare\|qty.*compare" \
  "$SRC" 2>/dev/null \
  | grep -i "withdraw\|transfer\|funds_out\|pay\|send" \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -5)

if [[ -n "$balance_check" ]]; then
  count=$(echo "$balance_check" | wc -l)
  record "PASS" "P-12 Balance validation" "$count balance check patterns in financial paths"
else
  record "FAIL" "P-12 Balance validation" "No balance validation found before withdrawals"
fi

# Check for negative amount validation
negative_check=$(grep -rn --include="$SRC_EXT" \
  "$NEGATIVE_AMOUNT_PATTERN\|validateAmount" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -5)

if [[ -n "$negative_check" ]]; then
  record "PASS" "P-12 Negative amount check" "Amount validation found"
else
  record "WARN" "P-12 Negative amount check" "No explicit negative/zero amount validation found"
fi

# Check for FOR UPDATE locking on financial queries
for_update=$(grep -rn --include="$SRC_EXT" \
  "$FOR_UPDATE_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -10)

if [[ -n "$for_update" ]]; then
  count=$(echo "$for_update" | wc -l)
  record "PASS" "P-12 Row locking" "$count row-locking patterns for financial operations"
else
  record "FAIL" "P-12 Row locking" "No FOR UPDATE or advisory lock patterns found"
fi

# Check for transaction ID generation (collision resistance)
txn_id=$(grep -rn --include="$SRC_EXT" \
  "generateTransactionId\|$SECURE_RANDOM_PATTERN\|SecureRandom.*transaction" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -5)

if [[ -n "$txn_id" ]]; then
  record "PASS" "P-12 Transaction IDs" "Collision-resistant transaction ID generation found"
else
  record "WARN" "P-12 Transaction IDs" "No secure transaction ID generation pattern found"
fi
