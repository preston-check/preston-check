#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-87
name: ISO Organizational Controls
description: Verifies ISMS scope, threat intelligence, supplier mgmt, cloud security, incident mgmt.
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
frameworks: ISO-27001:2022:5.1, ISO-27001:2022:5.37
PRESTON_META


# P-87: ISO 27001 Organizational Controls (A.5.x) Evidence
# Checks for ISMS documentation, risk register, threat intelligence, supplier management.
echo "P-87: ISO 27001 Organizational"
SRC="${SOURCE_DIR:-.}"

found=0
required=5

# A.5.1 — Information Security Policy
isp=$(find "$SRC" -maxdepth 5 \( -iname "*security*policy*" -o -iname "*isms*" -o -iname "*information*security*management*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$isp" ]] && found=$((found + 1))

# A.5.7 — Threat Intelligence
threat_intel=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "threat.*intel\|threat.*feed\|ioc\|indicator.*compromise\|cve.*check\|vulnerability.*feed\|osint" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
[[ -n "$threat_intel" ]] && found=$((found + 1))

# A.5.19-5.22 — Supplier/Third-party management
supplier=$(find "$SRC" -maxdepth 5 \( -iname "*supplier*" -o -iname "*vendor*assess*" -o -iname "*third*party*risk*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
supplier_code=$(grep -rn --include="*.java" --include="*.ts" \
  "vendor.*security\|supplier.*assess\|third.*party.*risk\|soc2.*report\|iso.*cert" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -1)
[[ -n "$supplier" || -n "$supplier_code" ]] && found=$((found + 1))

# A.5.23 — Cloud services security
cloud_sec=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.tf" --include="*.json" \
  "security.*group\|iam.*policy\|kms\|cloudtrail\|guardduty\|waf\|shield" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
[[ -n "$cloud_sec" ]] && found=$((found + 1))

# A.5.24-5.28 — Incident management
incident=$(find "$SRC" -maxdepth 5 \( -iname "*incident*" -o -iname "*ir*plan*" -o -iname "*response*plan*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
incident_code=$(grep -rn --include="*.java" --include="*.ts" \
  "incident.*response\|security.*incident\|breach.*notification\|forensic" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -1)
[[ -n "$incident" || -n "$incident_code" ]] && found=$((found + 1))

if [[ $found -ge 4 ]]; then
  record "PASS" "P-87 ISO organizational" "$found/$required organizational control evidence found"
elif [[ $found -ge 2 ]]; then
  record "WARN" "P-87 ISO organizational" "$found/$required — need: security policy, threat intel, supplier mgmt, cloud security, incident mgmt" "$(echo "$incident_code" | head -10)"
else
  record "WARN" "P-87 ISO organizational" "Only $found/$required ISO organizational control evidence found" "$(echo "$incident_code" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "threat.*intel|threat.*feed|ioc|indicator.*compromise|cve.*check|vulnerability.*feed|osint|vendor.*security|supplier.*assess|third.*party.*risk|soc2.*report|iso.*cert|incident.*response|security.*incident|breach.*notification|forensic" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-87 ISO Organizational Controls (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-87 ISO Organizational Controls (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "threat.*intel|threat.*feed|ioc|indicator.*compromise|cve.*check|vulnerability.*feed|osint|vendor.*security|supplier.*assess|third.*party.*risk|soc2.*report|iso.*cert|incident.*response|security.*incident|breach.*notification|forensic" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-87 ISO Organizational Controls (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-87 ISO Organizational Controls (Rust)" "No issues found in Rust files"
  fi
fi
