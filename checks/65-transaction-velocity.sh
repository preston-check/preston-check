#!/bin/bash
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
