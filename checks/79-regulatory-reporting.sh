#!/bin/bash
# P-79: Regulatory Reporting Readiness
# Financial institutions must file CTRs, SARs, and provide data to regulators on demand.
# Systems must be able to generate these reports automatically.
echo "P-79: Regulatory Reporting"
SRC="${SOURCE_DIR:-.}"

# Check for CTR (Currency Transaction Report) patterns
ctr=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "ctr\|currency.*transaction.*report\|10000\|threshold.*report\|reporting.*threshold\|large.*cash" \
  "$SRC" 2>/dev/null | grep -i "report\|threshold\|filing\|sar\|ctr\|fincen" \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$ctr" ]]; then
  record "PASS" "P-79 CTR readiness" "Currency Transaction Report patterns found"
else
  record "WARN" "P-79 CTR readiness" "No CTR filing patterns — BSA requires automatic CTR for transactions over $10,000"
fi

# Check for SAR (Suspicious Activity Report) mechanism
sar=$(grep -rn --include="*.java" --include="*.ts" \
  "sar\|suspicious.*activity\|suspicious.*report\|flag.*suspicious\|report.*suspicious\|alert.*compliance" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$sar" ]]; then
  record "PASS" "P-79 SAR mechanism" "SAR filing mechanism found"
else
  record "WARN" "P-79 SAR mechanism" "No SAR filing mechanism — must be able to file Suspicious Activity Reports"
fi

# Check for regulatory data export
reg_export=$(grep -rn --include="*.java" --include="*.ts" \
  "regulat.*report\|compliance.*report\|audit.*export\|transaction.*export\|generate.*report.*regulat" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$reg_export" ]]; then
  record "PASS" "P-79 Regulatory export" "Regulatory data export capability found"
else
  record "WARN" "P-79 Regulatory export" "No regulatory data export — must provide transaction data to regulators on demand"
fi
