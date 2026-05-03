#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-79
name: Regulatory Reporting
description: Detects CTR readiness, SAR mechanisms, regulatory export capabilities.
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
frameworks: SOC2:TSC-2017:CC2.3, ISO-27001:2022:5.31, NIST-CSF:2.0:ID.GV-3
PRESTON_META


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
  record "WARN" "P-79 CTR readiness" "No CTR filing patterns — BSA requires automatic CTR for transactions over $10,000" "$(echo "$ctr" | head -10)"
fi

# Check for SAR (Suspicious Activity Report) mechanism
sar=$(grep -rn --include="*.java" --include="*.ts" \
  "sar\|suspicious.*activity\|suspicious.*report\|flag.*suspicious\|report.*suspicious\|alert.*compliance" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$sar" ]]; then
  record "PASS" "P-79 SAR mechanism" "SAR filing mechanism found"
else
  record "WARN" "P-79 SAR mechanism" "No SAR filing mechanism — must be able to file Suspicious Activity Reports" "$(echo "$sar" | head -10)"
fi

# Check for regulatory data export
reg_export=$(grep -rn --include="*.java" --include="*.ts" \
  "regulat.*report\|compliance.*report\|audit.*export\|transaction.*export\|generate.*report.*regulat" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$reg_export" ]]; then
  record "PASS" "P-79 Regulatory export" "Regulatory data export capability found"
else
  record "WARN" "P-79 Regulatory export" "No regulatory data export — must provide transaction data to regulators on demand" "$(echo "$reg_export" | head -10)"
fi
