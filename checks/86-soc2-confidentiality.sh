#!/bin/bash
# P-86: SOC 2 Confidentiality Criteria (C1)
# Verifies data classification, confidentiality agreements, and DLP.
echo "P-86: SOC 2 Confidentiality"
SRC="${SOURCE_DIR:-.}"

# Check for data classification
classification=$(grep -rn --include="*.java" --include="*.ts" --include="*.md" --include="*.yml" \
  "data.*classif\|confidential\|internal.*only\|restricted\|public\|sensitive.*data\|classification.*level" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
class_doc=$(find "$SRC" -maxdepth 5 \( -iname "*data*classification*" -o -iname "*data*handling*" -o -iname "*information*classification*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
if [[ -n "$classification" || -n "$class_doc" ]]; then
  record "PASS" "P-86 Data classification" "Data classification patterns or documentation found"
else
  record "WARN" "P-86 Data classification" "No data classification system — need to label data by sensitivity level"
fi

# Check for NDA / confidentiality agreement references
nda=$(grep -rn --include="*.md" --include="*.txt" --include="*.java" --include="*.ts" \
  "NDA\|non.*disclosure\|confidentiality.*agreement\|proprietary" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$nda" ]]; then
  record "PASS" "P-86 Confidentiality agreements" "NDA/confidentiality agreement references found"
else
  record "WARN" "P-86 Confidentiality agreements" "No NDA or confidentiality agreement references"
fi

# Check for DLP (Data Loss Prevention) patterns
dlp=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "dlp\|data.*loss.*prevent\|exfiltrat\|data.*leakage\|@JsonIgnore\|@Transient\|redact\|mask\|sanitize" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$dlp" ]]; then
  record "PASS" "P-86 DLP controls" "Data leakage prevention patterns found (masking, redaction, @JsonIgnore)"
else
  record "WARN" "P-86 DLP controls" "No data leakage prevention patterns"
fi
