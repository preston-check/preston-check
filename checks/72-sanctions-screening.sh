#!/bin/bash
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
