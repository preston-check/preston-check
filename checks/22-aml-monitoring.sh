#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-22
name: AML Transaction Monitoring
description: Checks for CTR thresholds, structuring detection, SAR mechanisms.
category: live-monitoring
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: SOC2:TSC-2017:CC3.2, ISO-27001:2022:5.34, NIST-CSF:2.0:GV.RM-1
PRESTON_META


# P-22: AML Transaction Monitoring
# CTR thresholds, velocity/structuring detection, SAR flagging.
echo "P-22: AML Controls"
SRC="${SOURCE_DIR:-.}"

threshold=$(grep -rn --include="*.java" \
  "10000\|threshold\|REPORTING_LIMIT\|CTR\|suspicious.*amount\|AML_THRESHOLD" \
  "$SRC/Payments-logic" "$SRC/FireblocksSecureWalletWithdraw-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$threshold" ]]; then
  record "PASS" "P-22 Amount thresholds" "Transaction amount threshold checks found"
else
  record "WARN" "P-22 Amount thresholds" "No CTR/AML amount threshold checks found" "$(echo "$threshold" | head -10)"
fi

velocity=$(grep -rn --include="*.java" \
  "velocity\|structuring\|frequency.*check\|transaction.*count.*period\|CompanyLimit\|company_limits" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$velocity" ]]; then
  record "PASS" "P-22 Velocity checks" "Transaction velocity/limit checks found"
else
  record "WARN" "P-22 Velocity checks" "No velocity/structuring detection found" "$(echo "$velocity" | head -10)"
fi

sar=$(grep -rn --include="*.java" --include="*.sql" \
  "suspicious\|SAR\|flag.*transaction\|review.*queue\|compliance.*alert\|risk.*score\|behavior.*alert" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$sar" ]]; then
  record "PASS" "P-22 SAR mechanism" "Suspicious activity flagging found"
else
  record "WARN" "P-22 SAR mechanism" "No suspicious activity reporting mechanism" "$(echo "$sar" | head -10)"
fi
