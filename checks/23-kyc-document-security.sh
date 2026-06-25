#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-23
name: KYC Document Security
description: Checks S3 encryption, presigned URL duration, file type validation.
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
frameworks: PCI-DSS:4.0:3.4, SOC2:TSC-2017:CC6.5, ISO-27001:2022:8.10, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-1
PRESTON_META


# P-23: KYC Document Security
# S3 encryption, presigned URL expiry, file type validation, size limits.
echo "P-23: KYC Document Security"
SRC="${SOURCE_DIR:-.}"

s3_enc=$(grep -rn --include="*.java" \
  "ServerSideEncryption\|serverSideEncryption\|SSE\|aws:kms" \
  "$SRC/Registration" "$SRC/FileManager" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$s3_enc" ]]; then
  record "PASS" "P-23 S3 encryption" "S3 server-side encryption configured"
else
  record "WARN" "P-23 S3 encryption" "No S3 encryption enforcement found for KYC documents" "$(echo "$s3_enc" | head -10)"
fi

presign=$(grep -rn --include="*.java" \
  "signatureDuration\|Duration.of\|presigned\|presignGetObject" \
  "$SRC/Registration" "$SRC/FileManager" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$presign" ]]; then
  long_presign=$(echo "$presign" | grep -i "ofDays\|ofHours.*[2-9]\|ofHours.*[1-9][0-9]")
  if [[ -n "$long_presign" ]]; then
    record "WARN" "P-23 Presigned URL expiry" "Presigned URLs expire > 1 hour — reduce for KYC documents" "$(echo "$presign" | head -10)"
  else
    record "PASS" "P-23 Presigned URL expiry" "Presigned URL duration appears reasonable"
  fi
fi

filetype=$(grep -rn --include="*.java" \
  "contentType\|getContentType\|allowedTypes\|MIME\|file.*extension\|accept.*image\|accept.*pdf" \
  "$SRC/Registration" "$SRC/FileManager" 2>/dev/null \
  | grep -i "valid\|check\|allow\|restrict\|reject\|whitelist" \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$filetype" ]]; then
  record "PASS" "P-23 File type validation" "Upload file type validation found"
else
  record "WARN" "P-23 File type validation" "No file type validation on document uploads" "$(echo "$filetype" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "ServerSideEncryption|SSE|aws:kms|presigned|PresignGetObject|contentType|allowedTypes|MIME|fileExtension" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-23 KYC document security (Go)" "KYC document security patterns found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "WARN" "P-23 KYC document security (Go)" "No KYC document security patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "ServerSideEncryption|SSE|aws_kms|presigned|presign_get_object|content_type|allowed_types|mime|file_extension" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-23 KYC document security (Rust)" "KYC document security patterns found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "WARN" "P-23 KYC document security (Rust)" "No KYC document security patterns found in Rust files"
  fi
fi
