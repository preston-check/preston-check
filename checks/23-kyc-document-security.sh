#!/bin/bash
# P-23: KYC Document Security
# S3 encryption, presigned URL expiry, file type validation, size limits.
echo "P-23: KYC Document Security"
SRC="${SOURCE_DIR:-.}"

s3_enc=$(grep -rn --include="*.java" --max-count=5 \
  "ServerSideEncryption\|serverSideEncryption\|SSE\|aws:kms" \
  "$SRC/Registration" "$SRC/FileManager" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$s3_enc" ]]; then
  record "PASS" "P-23 S3 encryption" "S3 server-side encryption configured"
else
  record "WARN" "P-23 S3 encryption" "No S3 encryption enforcement found for KYC documents"
fi

presign=$(grep -rn --include="*.java" --max-count=5 \
  "signatureDuration\|Duration.of\|presigned\|presignGetObject" \
  "$SRC/Registration" "$SRC/FileManager" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$presign" ]]; then
  long_presign=$(echo "$presign" | grep -i "ofDays\|ofHours.*[2-9]\|ofHours.*[1-9][0-9]")
  if [[ -n "$long_presign" ]]; then
    record "WARN" "P-23 Presigned URL expiry" "Presigned URLs expire > 1 hour — reduce for KYC documents"
  else
    record "PASS" "P-23 Presigned URL expiry" "Presigned URL duration appears reasonable"
  fi
fi

filetype=$(grep -rn --include="*.java" --max-count=5 \
  "contentType\|getContentType\|allowedTypes\|MIME\|file.*extension\|accept.*image\|accept.*pdf" \
  "$SRC/Registration" "$SRC/FileManager" 2>/dev/null \
  | grep -i "valid\|check\|allow\|restrict\|reject\|whitelist" \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$filetype" ]]; then
  record "PASS" "P-23 File type validation" "Upload file type validation found"
else
  record "WARN" "P-23 File type validation" "No file type validation on document uploads"
fi
