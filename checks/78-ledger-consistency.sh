#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-78
name: Ledger Consistency
description: Detects atomic balance updates, drift detection, orphans, idempotent updates.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6
PRESTON_META


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
  record "WARN" "P-78 Atomic balance" "No atomic balance updates — concurrent operations can corrupt balances" "$(echo "$atomic_balance" | head -10)"
fi

# Check for balance drift detection
drift=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "drift\|discrepancy\|mismatch.*balance\|balance.*check\|integrity.*check\|sum.*check\|zero.*sum\|balance.*verify" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$drift" ]]; then
  record "PASS" "P-78 Drift detection" "Balance drift/discrepancy detection found"
else
  record "WARN" "P-78 Drift detection" "No balance drift detection — should periodically verify sum(credits) = sum(debits)" "$(echo "$drift" | head -10)"
fi

# Check for orphan transaction detection
orphan=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "orphan\|dangling\|unmatched\|unlinked\|missing.*parent\|missing.*counterpart" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$orphan" ]]; then
  record "PASS" "P-78 Orphan detection" "Orphan transaction detection found"
else
  record "WARN" "P-78 Orphan detection" "No orphan transaction detection — unmatched entries indicate ledger corruption" "$(echo "$orphan" | head -10)"
fi

# Check for idempotent balance updates
idempotent_balance=$(grep -rn --include="*.java" --include="*.ts" \
  "idempoten.*balance\|idempoten.*credit\|idempoten.*debit\|unique.*transaction_id\|ON CONFLICT.*transaction" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$idempotent_balance" ]]; then
  record "PASS" "P-78 Idempotent ledger" "Idempotent ledger updates found"
else
  record "WARN" "P-78 Idempotent ledger" "No idempotent ledger update pattern — retries could create duplicate entries" "$(echo "$idempotent_balance" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "BeginTx|db\.Begin|sql\.Tx|atomic.*balance|balance.*lock|drift|discrepancy|mismatch.*balance|balance.*check|integrity.*check|sum.*check|zero.*sum|balance.*verify|orphan|dangling|unmatched|unlinked|missing.*parent|idempoten|ON CONFLICT.*transaction|unique.*transaction" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-78 Ledger consistency (Go)" "$_go_count pattern(s) found in Go code"
  else
    record "WARN" "P-78 Ledger consistency (Go)" "No ledger consistency/atomic balance patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "sqlx::Transaction|begin_transaction|atomic.*balance|balance.*lock|drift|discrepancy|mismatch.*balance|balance.*check|integrity.*check|sum.*check|zero.*sum|balance.*verify|orphan|dangling|unmatched|unlinked|missing.*parent|idempoten|ON CONFLICT.*transaction|unique.*transaction" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-78 Ledger consistency (Rust)" "$_rs_count pattern(s) found in Rust code"
  else
    record "WARN" "P-78 Ledger consistency (Rust)" "No ledger consistency/atomic balance patterns found in Rust files"
  fi
fi
