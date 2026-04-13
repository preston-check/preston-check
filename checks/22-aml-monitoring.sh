#!/bin/bash
# P-22: AML Transaction Monitoring
# CTR thresholds, velocity/structuring detection, SAR flagging.
echo "P-22: AML Controls"
SRC="${SOURCE_DIR:-.}"

threshold=$(grep -rn --include="*.java" --max-count=5 \
  "10000\|threshold\|REPORTING_LIMIT\|CTR\|suspicious.*amount\|AML_THRESHOLD" \
  "$SRC/Payments-logic" "$SRC/FireblocksSecureWalletWithdraw-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$threshold" ]]; then
  record "PASS" "P-22 Amount thresholds" "Transaction amount threshold checks found"
else
  record "WARN" "P-22 Amount thresholds" "No CTR/AML amount threshold checks found"
fi

velocity=$(grep -rn --include="*.java" --max-count=5 \
  "velocity\|structuring\|frequency.*check\|transaction.*count.*period\|CompanyLimit\|company_limits" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$velocity" ]]; then
  record "PASS" "P-22 Velocity checks" "Transaction velocity/limit checks found"
else
  record "WARN" "P-22 Velocity checks" "No velocity/structuring detection found"
fi

sar=$(grep -rn --include="*.java" --include="*.sql" --max-count=5 \
  "suspicious\|SAR\|flag.*transaction\|review.*queue\|compliance.*alert\|risk.*score\|behavior.*alert" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$sar" ]]; then
  record "PASS" "P-22 SAR mechanism" "Suspicious activity flagging found"
else
  record "WARN" "P-22 SAR mechanism" "No suspicious activity reporting mechanism"
fi
