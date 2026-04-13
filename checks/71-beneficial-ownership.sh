#!/bin/bash
# P-71: Beneficial Ownership & UBO Tracking
# FinCEN CDD Rule requires identification of beneficial owners (25%+ ownership).
# Financial systems must track and verify the real people behind accounts.
echo "P-71: Beneficial Ownership"
SRC="${SOURCE_DIR:-.}"

# Check for beneficial owner tracking
ubo=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "beneficial.*owner\|ubo\|ultimate.*owner\|controlling.*person\|significant.*owner\|ownership.*percent" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$ubo" ]]; then
  record "PASS" "P-71 UBO tracking" "Beneficial ownership tracking found"
else
  record "WARN" "P-71 UBO tracking" "No beneficial ownership tracking — FinCEN CDD Rule requires UBO identification for 25%+ owners"
fi

# Check for company/entity KYC (not just individual KYC)
entity_kyc=$(grep -rn --include="*.java" --include="*.ts" \
  "company.*kyc\|entity.*verify\|corporate.*verification\|business.*verify\|ein\|tax.*id.*verify" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$entity_kyc" ]]; then
  record "PASS" "P-71 Entity verification" "Corporate/entity verification found"
else
  record "WARN" "P-71 Entity verification" "No corporate entity verification patterns (EIN, business verification)"
fi
