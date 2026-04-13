#!/bin/bash
# P-61: Privacy & Consent Mechanisms — SOC 2 P1-P8, ISO 27001 A.5.34, GDPR Art 6/7
# Checks for consent management, DSAR handling, data export.
echo "P-61: Privacy & Consent"
SRC="${SOURCE_DIR:-.}"

# Check for consent management
consent=$(grep -rn --include="*.java" --include="*.ts" --include="*.tsx" \
  "consent\|privacy.*accept\|terms.*accept\|gdpr\|data.*subject\|dsar\|right.*erasure\|right.*forget" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$consent" ]]; then
  record "PASS" "P-61 Consent management" "Privacy/consent handling patterns found"
else
  record "WARN" "P-61 Consent management" "No consent management or DSAR handling patterns found"
fi

# Check for data export capability
data_export=$(grep -rn --include="*.java" --include="*.ts" \
  "export.*data\|download.*data\|data.*portability\|generateReport\|user.*export" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$data_export" ]]; then
  record "PASS" "P-61 Data portability" "Data export capability found"
else
  record "WARN" "P-61 Data portability" "No data export/portability mechanism found (GDPR Art 20)"
fi
