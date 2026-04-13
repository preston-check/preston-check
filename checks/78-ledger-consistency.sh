#!/bin/bash
# P-78: Ledger Consistency & Zero-Sum Validation
# Every debit must have a corresponding credit. The sum of all movements must be zero.
# Inconsistent ledgers indicate bugs, theft, or system corruption.
echo "P-78: Ledger Consistency"
SRC="${SOURCE_DIR:-.}"

# Check for balance calculation atomicity
atomic_balance=$(grep -rn --include="*.java" --include="*.ts" \
  "@Transactional\|BEGIN\|COMMIT\|FOR UPDATE.*balance\|LOCK.*balance\|atomic.*balance\|balance.*lock" \
  "$SRC" 2>/dev/null | grep -i "balance\|portfolio\|ledger\|account" \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$atomic_balance" ]]; then
  record "PASS" "P-78 Atomic balance" "Balance updates use transactions/locking"
else
  record "WARN" "P-78 Atomic balance" "No atomic balance updates — concurrent operations can corrupt balances"
fi

# Check for balance drift detection
drift=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "drift\|discrepancy\|mismatch.*balance\|balance.*check\|integrity.*check\|sum.*check\|zero.*sum\|balance.*verify" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$drift" ]]; then
  record "PASS" "P-78 Drift detection" "Balance drift/discrepancy detection found"
else
  record "WARN" "P-78 Drift detection" "No balance drift detection — should periodically verify sum(credits) = sum(debits)"
fi

# Check for orphan transaction detection
orphan=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "orphan\|dangling\|unmatched\|unlinked\|missing.*parent\|missing.*counterpart" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$orphan" ]]; then
  record "PASS" "P-78 Orphan detection" "Orphan transaction detection found"
else
  record "WARN" "P-78 Orphan detection" "No orphan transaction detection — unmatched entries indicate ledger corruption"
fi

# Check for idempotent balance updates
idempotent_balance=$(grep -rn --include="*.java" --include="*.ts" \
  "idempoten.*balance\|idempoten.*credit\|idempoten.*debit\|unique.*transaction_id\|ON CONFLICT.*transaction" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$idempotent_balance" ]]; then
  record "PASS" "P-78 Idempotent ledger" "Idempotent ledger updates found"
else
  record "WARN" "P-78 Idempotent ledger" "No idempotent ledger update pattern — retries could create duplicate entries"
fi
