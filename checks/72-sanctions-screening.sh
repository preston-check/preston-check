#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-72
name: Sanctions Screening
description: Detects OFAC, PEP, country restriction enforcement on transactions and registration.
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
  record "WARN" "P-72 Sanctions screening" "No OFAC/sanctions screening — mandatory for all financial institutions"
fi

# Check for PEP screening
pep=$(grep -rn --include="*.java" --include="*.ts" \
  "pep\|politically.*exposed\|enhanced.*due.*diligence\|edd\|high.*risk.*customer\|risk.*rating" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$pep" ]]; then
  record "PASS" "P-72 PEP screening" "PEP/enhanced due diligence patterns found"
else
  record "WARN" "P-72 PEP screening" "No PEP screening — politically exposed persons require enhanced monitoring"
fi

# Check for country-based restrictions
country_block=$(grep -rn --include="*.java" --include="*.ts" \
  "blocked.*countr\|restricted.*countr\|country.*whitelist\|country.*blacklist\|allowed.*countr\|forbidden.*countr" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$country_block" ]]; then
  record "PASS" "P-72 Country restrictions" "Country-based restrictions found"
else
  record "WARN" "P-72 Country restrictions" "No country-based transaction restrictions"
fi
