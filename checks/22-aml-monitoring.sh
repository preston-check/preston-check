#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-22
name: AML Transaction Monitoring
description: Checks for CTR thresholds, structuring detection, SAR mechanisms.
category: live-monitoring
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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

# --- Go ---
# Use AML-specific identifiers only. Bare "10000", "velocity", and "suspicious"
# are too common in general Go code and produce false PASSes.
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules \
    -E "AML_THRESHOLD|CTR_THRESHOLD|ctrLimit|amlThreshold|structuringDetect|velocityCheck|sarFlag|riskScore|risk_score|companyLimit|SuspiciousActivity|flagTransaction" \
    "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-22 AML transaction monitoring (Go)" "AML monitoring patterns found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "WARN" "P-22 AML transaction monitoring (Go)" "No AML monitoring patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target \
    -E "AML_THRESHOLD|CTR_THRESHOLD|ctr_limit|aml_threshold|structuring_detect|velocity_check|sar_flag|risk_score|company_limit|suspicious_activity|flag_transaction" \
    "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-22 AML transaction monitoring (Rust)" "AML monitoring patterns found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "WARN" "P-22 AML transaction monitoring (Rust)" "No AML monitoring patterns found in Rust files"
  fi
fi
