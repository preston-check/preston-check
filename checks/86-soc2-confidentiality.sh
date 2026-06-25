#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-86
name: SOC 2 Confidentiality
description: Verifies data classification, NDA references, DLP controls.
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
frameworks: SOC2:TSC-2017:C1.1, SOC2:TSC-2017:C1.2, ISO-27001:2022:5.12, NIST-CSF:2.0:PR.DS-5
PRESTON_META


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
  record "WARN" "P-86 Data classification" "No data classification system — need to label data by sensitivity level" "$(echo "$class_doc" | head -10)"
fi

# Check for NDA / confidentiality agreement references
nda=$(grep -rn --include="*.md" --include="*.txt" --include="*.java" --include="*.ts" \
  "NDA\|non.*disclosure\|confidentiality.*agreement\|proprietary" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$nda" ]]; then
  record "PASS" "P-86 Confidentiality agreements" "NDA/confidentiality agreement references found"
else
  record "WARN" "P-86 Confidentiality agreements" "No NDA or confidentiality agreement references" "$(echo "$nda" | head -10)"
fi

# Check for DLP (Data Loss Prevention) patterns
dlp=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "dlp\|data.*loss.*prevent\|exfiltrat\|data.*leakage\|@JsonIgnore\|@Transient\|redact\|mask\|sanitize" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$dlp" ]]; then
  record "PASS" "P-86 DLP controls" "Data leakage prevention patterns found (masking, redaction, @JsonIgnore)"
else
  record "WARN" "P-86 DLP controls" "No data leakage prevention patterns" "$(echo "$dlp" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "data.*classif|confidential|internal.*only|restricted|sensitive.*data|classification.*level|NDA|non.*disclosure|confidentiality.*agreement|proprietary|dlp|data.*loss.*prevent|exfiltrat|data.*leakage|json:\"-\"|redact|mask|sanitize" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-86 SOC 2 confidentiality (Go)" "$_go_count pattern(s) found in Go code"
  else
    record "WARN" "P-86 SOC 2 confidentiality (Go)" "No data classification/DLP/confidentiality patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "data.*classif|confidential|internal.*only|restricted|sensitive.*data|classification.*level|NDA|non.*disclosure|confidentiality.*agreement|proprietary|dlp|data.*loss.*prevent|exfiltrat|data.*leakage|skip_serializing|serde.*skip|redact|mask|sanitize" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-86 SOC 2 confidentiality (Rust)" "$_rs_count pattern(s) found in Rust code"
  else
    record "WARN" "P-86 SOC 2 confidentiality (Rust)" "No data classification/DLP/confidentiality patterns found in Rust files"
  fi
fi
