#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-65
name: Transaction Velocity
description: Detects rapid-fire transaction patterns, structuring, missing cooling periods.
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
frameworks: PCI-DSS:4.0:10.6.1, SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.16, NIST-CSF:2.0:DE.AE-3, CIS-v8:8.11
PRESTON_META


# P-65: Transaction Velocity & Structuring Detection
# Checks for velocity limits, structuring detection patterns, and smurfing prevention.
# Financial systems MUST detect when a user splits transactions to stay below reporting thresholds.
echo "P-65: Transaction Velocity"
SRC="${SOURCE_DIR:-.}"

# Check for velocity/frequency limits on transactions
velocity=$(grep -rn --include="$SRC_EXT" \
  "velocity\|frequency.*limit\|tx.*per.*day\|daily.*limit\|rolling.*window\|24.*hour\|rate.*check.*amount\|transaction.*count\|HackingDetectionService.checkSessionActivity\|HackingDetectionService.checkLoginAttempt\|checkWithdrawalProbe\|session_polling\|failed_login_burst" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$velocity" ]]; then
  record "PASS" "P-65 Velocity limits" "Transaction velocity/frequency limiting found"
else
  record "FAIL" "P-65 Velocity limits" "No transaction velocity monitoring — must detect rapid-fire transactions"
fi

# Check for structuring detection (splitting transactions to avoid CTR thresholds)
structuring=$(grep -rn --include="$SRC_EXT" \
  "structur\|smurfing\|threshold.*aggregate\|cumulative.*amount\|rolling.*sum\|10000\|9999\|9800" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*\|css\|html" | head -3)
if [[ -n "$structuring" ]]; then
  record "PASS" "P-65 Structuring detection" "Transaction structuring detection patterns found"
else
  record "WARN" "P-65 Structuring detection" "No structuring detection — must aggregate transactions to detect threshold avoidance (BSA/AML)"
fi

# Check for cooling period between same-type transactions
cooling=$(grep -rn --include="$SRC_EXT" \
  "cooldown\|cool.*period\|minimum.*interval\|min.*time.*between\|last.*transaction.*time\|recent.*withdraw" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -3)
if [[ -n "$cooling" ]]; then
  record "PASS" "P-65 Transaction cooldown" "Cooling period between transactions enforced"
else
  record "WARN" "P-65 Transaction cooldown" "No cooling period between rapid consecutive transactions"
fi
