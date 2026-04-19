#!/bin/bash
# P-70: Settlement Finality & Immutability
# Completed transactions must be irreversible. No DELETE, no qty zeroing, no status rewind.
# Financial regulators require clear settlement finality for every transaction type.
echo "P-70: Settlement Finality"
SRC="${SOURCE_DIR:-.}"

# Check for transaction deletion (never allowed on completed transactions)
tx_delete=$(grep -rn --include="*.java" --include="*.ts" \
  "\.delete(.*hold\|\.delete(.*fee\|\.delete(.*transaction\|DELETE FROM.*portfolio_asset_transaction" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|migration\|CREATE\|ALTER\|cancel\|removeHold\|HOLD\|hold.*release\|Whitelist Rejected\|delete(hold)\|delete(fee)\|delete(fixedfee)" | head -5)
if [[ -z "$tx_delete" ]]; then
  record "PASS" "P-70 No tx deletion" "No transaction deletion patterns found"
else
  count=$(echo "$tx_delete" | wc -l | tr -d ' ')
  record "FAIL" "P-70 No tx deletion" "$count transaction deletion patterns — settled transactions must be immutable"
fi

# Check for status reversal protection (completed → pending is never allowed)
# Exclude legitimate payment reversal statuses (reverted is a valid terminal state)
status_rewind=$(grep -rn --include="*.java" --include="*.ts" \
  "PROCESSED.*PENDING\|COMPLETED.*PENDING\|SETTLED.*PENDING\|status.*rollback" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|reverted\|REVERSED\|REFUND" | head -3)
if [[ -z "$status_rewind" ]]; then
  record "PASS" "P-70 No status rewind" "No forward-to-backward status transitions found"
else
  count=$(echo "$status_rewind" | wc -l | tr -d ' ')
  record "FAIL" "P-70 No status rewind" "$count status rewind patterns — completed transactions must not revert to pending"
fi

# Check for qty zeroing on HOLDs (should change type, not zero qty)
qty_zero=$(grep -rn --include="*.java" \
  "setQty(0)\|setQty(BigDecimal.ZERO)\|qty.*=.*0\|qty.*=.*BigDecimal.ZERO" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -z "$qty_zero" ]]; then
  record "PASS" "P-70 No qty zeroing" "No transaction qty zeroing found"
else
  count=$(echo "$qty_zero" | wc -l | tr -d ' ')
  record "WARN" "P-70 No qty zeroing" "$count qty zeroing patterns — HOLD resolution should change transaction_type, not zero qty"
fi

# Check for append-only enforcement (DB trigger or application guard)
append_only=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "append.only\|prevent_delete\|prevent_update\|immutable\|before.*delete.*raise\|BEFORE DELETE.*EXCEPTION" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$append_only" ]]; then
  record "PASS" "P-70 Append-only" "Append-only ledger enforcement found"
else
  record "WARN" "P-70 Append-only" "No explicit append-only ledger enforcement (DB trigger recommended)"
fi
