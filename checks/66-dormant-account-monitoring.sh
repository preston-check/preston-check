#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-66
name: Dormant Account Monitoring
description: Detects reactivation anomalies, step-up auth on long-dormant accounts.
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
frameworks: SOC2:TSC-2017:CC6.2, ISO-27001:2022:5.16, NIST-CSF:2.0:DE.CM-3, CIS-v8:6.2
PRESTON_META


# P-66: Dormant Account Reactivation Monitoring
# Accounts that go dormant then suddenly become active with large transactions
# are a classic money laundering indicator. Financial systems MUST flag this.
echo "P-66: Dormant Account Monitoring"
SRC="${SOURCE_DIR:-.}"

# Check for dormant/inactive account detection
dormant=$(grep -rn --include="*.java" --include="*.ts" \
  "dormant\|inactive.*account\|last.*login\|last.*activity\|days.*since\|reactivat\|account.*age\|stale.*account" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$dormant" ]]; then
  record "PASS" "P-66 Dormant detection" "Dormant/inactive account monitoring found"
else
  record "WARN" "P-66 Dormant detection" "No dormant account reactivation monitoring — flag accounts resuming activity after prolonged inactivity" "$(echo "$dormant" | head -10)"
fi

# Check for step-up authentication on reactivation
stepup=$(grep -rn --include="*.java" --include="*.ts" \
  "step.*up.*auth\|re.*verify\|additional.*verification\|enhanced.*due.*diligence\|edd\|re.*kyc" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$stepup" ]]; then
  record "PASS" "P-66 Step-up auth" "Enhanced verification patterns found"
else
  record "WARN" "P-66 Step-up auth" "No step-up authentication for high-risk activities (reactivation, large tx, new destination)" "$(echo "$stepup" | head -10)"
fi

# Check for login anomaly detection
login_anomaly=$(grep -rn --include="*.java" --include="*.ts" \
  "unusual.*login\|new.*device\|new.*ip\|geo.*anomal\|impossible.*travel\|login.*alert" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$login_anomaly" ]]; then
  record "PASS" "P-66 Login anomaly" "Login anomaly detection found"
else
  record "WARN" "P-66 Login anomaly" "No login anomaly detection (new device/IP/geolocation changes)" "$(echo "$login_anomaly" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "dormant|inactive.*account|last.*login|last.*activity|days.*since|reactivat|account.*age|stale.*account|step.*up.*auth|re.*verify|unusual.*login|new.*device|new.*ip" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-66 Dormant Account Monitoring (Go)" "Dormant account detection or login anomaly patterns found in Go code"
  else
    record "WARN" "P-66 Dormant Account Monitoring (Go)" "No dormant account monitoring or step-up auth patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "dormant|inactive.*account|last.*login|last.*activity|days.*since|reactivat|account.*age|stale.*account|step.*up.*auth|re.*verify|unusual.*login|new.*device|new.*ip" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-66 Dormant Account Monitoring (Rust)" "Dormant account detection or login anomaly patterns found in Rust code"
  else
    record "WARN" "P-66 Dormant Account Monitoring (Rust)" "No dormant account monitoring or step-up auth patterns found in Rust files"
  fi
fi
