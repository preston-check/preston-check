#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-74
name: Proof of Reserves
description: Detects balance reconciliation, overdraft prevention, double-entry patterns.
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
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6
PRESTON_META


# P-74: Proof of Reserves & Balance Integrity
# A financial platform must be able to prove it holds enough assets to cover all client balances.
# Internal balances must match external (custodian/blockchain/bank) balances.
echo "P-74: Proof of Reserves"
SRC="${SOURCE_DIR:-.}"

# Check for balance reconciliation
reconciliation=$(grep -rn --include="*.java" --include="*.ts" \
  "reconcil\|balance.*check\|proof.*reserve\|external.*balance\|custody.*balance\|verify.*balance\|balance.*mismatch" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$reconciliation" ]]; then
  record "PASS" "P-74 Balance reconciliation" "Balance reconciliation patterns found"
else
  record "WARN" "P-74 Balance reconciliation" "No balance reconciliation — platform must prove reserves match liabilities" "$(echo "$reconciliation" | head -10)"
fi

# Check for overdraft/negative balance prevention
overdraft=$(grep -rn --include="*.java" --include="*.ts" \
  "negative.*balance\|overdraft\|insufficient.*fund\|balance.*<.*0\|balance.*less.*than\|not.*enough" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$overdraft" ]]; then
  record "PASS" "P-74 Overdraft prevention" "Negative balance prevention found"
else
  record "WARN" "P-74 Overdraft prevention" "No explicit negative balance prevention" "$(echo "$overdraft" | head -10)"
fi

# Check for double-entry bookkeeping pattern
double_entry=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "double.*entry\|debit.*credit\|contra.*entry\|journal.*entry\|ledger.*entry\|offsetting" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$double_entry" ]]; then
  record "PASS" "P-74 Double-entry" "Double-entry bookkeeping patterns found"
else
  record "WARN" "P-74 Double-entry" "No double-entry bookkeeping — every financial movement should have a matching contra entry" "$(echo "$double_entry" | head -10)"
fi
