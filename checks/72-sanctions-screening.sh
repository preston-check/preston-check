#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-72
name: Sanctions Screening
description: Detects OFAC, PEP, country restriction enforcement on transactions and registration.
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
frameworks: SOC2:TSC-2017:CC2.3, ISO-27001:2022:5.31, NIST-CSF:2.0:ID.GV-3
PRESTON_META


# P-72: Sanctions & PEP Screening
# OFAC, EU, UN sanctions lists must be checked before every outbound payment.
# PEP (Politically Exposed Persons) screening is mandatory for enhanced due diligence.
echo "P-72: Sanctions Screening"
SRC="${SOURCE_DIR:-.}"

# Check for sanctions screening
sanctions=$(grep -rn --include="*.java" --include="*.ts" \
  "ofac\|sanction\|sdn.*list\|blocked.*person\|denied.*party\|embargo\|restricted.*country" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$sanctions" ]]; then
  record "PASS" "P-72 Sanctions screening" "OFAC/sanctions screening patterns found"
else
  record "WARN" "P-72 Sanctions screening" "No OFAC/sanctions screening — mandatory for all financial institutions" "$(echo "$sanctions" | head -10)"
fi

# Check for PEP screening
pep=$(grep -rn --include="*.java" --include="*.ts" \
  "pep\|politically.*exposed\|enhanced.*due.*diligence\|edd\|high.*risk.*customer\|risk.*rating" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$pep" ]]; then
  record "PASS" "P-72 PEP screening" "PEP/enhanced due diligence patterns found"
else
  record "WARN" "P-72 PEP screening" "No PEP screening — politically exposed persons require enhanced monitoring" "$(echo "$pep" | head -10)"
fi

# Check for country-based restrictions
country_block=$(grep -rn --include="*.java" --include="*.ts" \
  "blocked.*countr\|restricted.*countr\|country.*whitelist\|country.*blacklist\|allowed.*countr\|forbidden.*countr" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$country_block" ]]; then
  record "PASS" "P-72 Country restrictions" "Country-based restrictions found"
else
  record "WARN" "P-72 Country restrictions" "No country-based transaction restrictions" "$(echo "$country_block" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "ofac|sanction|sdn.*list|blocked.*person|embargo|pep|politically.*exposed|enhanced.*due.*diligence|blocked.*countr|restricted.*countr|country.*whitelist" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-72 Sanctions Screening (Go)" "OFAC/PEP/country restriction patterns found in Go code"
  else
    record "WARN" "P-72 Sanctions Screening (Go)" "No sanctions screening or PEP/country restriction patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "ofac|sanction|sdn.*list|blocked.*person|embargo|pep|politically.*exposed|enhanced.*due.*diligence|blocked.*countr|restricted.*countr|country.*whitelist" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-72 Sanctions Screening (Rust)" "OFAC/PEP/country restriction patterns found in Rust code"
  else
    record "WARN" "P-72 Sanctions Screening (Rust)" "No sanctions screening or PEP/country restriction patterns found in Rust files"
  fi
fi
