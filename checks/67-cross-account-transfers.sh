#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-67
name: Cross-Account Transfers
description: Detects money-mule patterns, layering indicators, beneficiary changes.
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
    record "WARN" "P-67 Transfer monitoring" "Cross-account transfers exist but monitoring not evident" "$(echo "$monitored" | head -10)"
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
  record "WARN" "P-67 Layering detection" "No rapid deposit→withdraw detection — classic money laundering pattern" "$(echo "$layering" | head -10)"
fi

# Check for beneficiary change monitoring
beneficiary=$(grep -rn --include="*.java" --include="*.ts" \
  "beneficiary.*change\|destination.*change\|new.*recipient\|whitelist.*add\|address.*change" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$beneficiary" ]]; then
  record "PASS" "P-67 Beneficiary monitoring" "Beneficiary change monitoring found"
else
  record "WARN" "P-67 Beneficiary monitoring" "No beneficiary/destination change monitoring" "$(echo "$beneficiary" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "cross.*account|internal.*transfer|layer|deposit.*withdraw|beneficiary.*change|destination.*change|monitor.*transfer|audit.*transfer" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-67 AML / Money Mule Detection (Go)" "Transfer monitoring patterns found in Go code"
  else
    record "WARN" "P-67 AML / Money Mule Detection (Go)" "No AML transfer monitoring patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "cross.*account|internal.*transfer|layer|deposit.*withdraw|beneficiary.*change|destination.*change|monitor.*transfer|audit.*transfer" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-67 AML / Money Mule Detection (Rust)" "Transfer monitoring patterns found in Rust code"
  else
    record "WARN" "P-67 AML / Money Mule Detection (Rust)" "No AML transfer monitoring patterns found in Rust files"
  fi
fi
