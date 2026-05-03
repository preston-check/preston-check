#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-67
name: Cross-Account Transfers
description: Detects money-mule patterns, layering indicators, beneficiary changes.
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
frameworks: SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.16, NIST-CSF:2.0:DE.AE-2
PRESTON_META


# P-67: Cross-Account Transfer & Money Mule Detection
# Detects patterns where funds move through intermediary accounts rapidly.
# Layering (deposit → immediate withdraw to different account) is a top AML red flag.
echo "P-67: Cross-Account Transfers"
SRC="${SOURCE_DIR:-.}"

# Check for cross-account transfer monitoring
cross_account=$(grep -rn --include="*.java" --include="*.ts" \
  "cross.*account\|internal.*transfer\|account.*to.*account\|peer.*to.*peer\|p2p.*transfer\|inter.*account" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$cross_account" ]]; then
  # Check if there's monitoring on these transfers
  monitored=$(grep -rn --include="*.java" --include="*.ts" \
    "monitor\|alert\|flag\|suspicious\|review\|log.*transfer\|audit.*transfer" \
    "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
  if [[ -n "$monitored" ]]; then
    record "PASS" "P-67 Transfer monitoring" "Cross-account transfers are monitored"
  else
    record "WARN" "P-67 Transfer monitoring" "Cross-account transfers exist but monitoring not evident"
  fi
else
  record "PASS" "P-67 Transfer monitoring" "No cross-account transfer patterns found"
fi

# Check for rapid deposit-then-withdraw detection (layering)
layering=$(grep -rn --include="*.java" --include="*.ts" \
  "deposit.*withdraw\|layer\|pass.*through\|rapid.*movement\|quick.*turn\|same.*day.*withdraw" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$layering" ]]; then
  record "PASS" "P-67 Layering detection" "Deposit-then-withdraw (layering) detection found"
else
  record "WARN" "P-67 Layering detection" "No rapid deposit→withdraw detection — classic money laundering pattern"
fi

# Check for beneficiary change monitoring
beneficiary=$(grep -rn --include="*.java" --include="*.ts" \
  "beneficiary.*change\|destination.*change\|new.*recipient\|whitelist.*add\|address.*change" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$beneficiary" ]]; then
  record "PASS" "P-67 Beneficiary monitoring" "Beneficiary change monitoring found"
else
  record "WARN" "P-67 Beneficiary monitoring" "No beneficiary/destination change monitoring"
fi
