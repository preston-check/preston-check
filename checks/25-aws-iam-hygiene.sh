#!/bin/bash
# P-25: AWS IAM & Credential Hygiene
# Static credentials vs IAM roles, wildcard policies, Secrets Manager usage.
echo "P-25: AWS IAM Hygiene"
SRC="${SOURCE_DIR:-.}"

static_creds=$(grep -rn --include="*.java" \
  "AwsBasicCredentials\|StaticCredentialsProvider\|BasicAWSCredentials\|AWSStaticCredentials" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|//\|/\*" | head -5)
if [[ -z "$static_creds" ]]; then
  record "PASS" "P-25 No static AWS creds" "No static AWS credentials — using IAM roles"
else
  count=$(echo "$static_creds" | wc -l)
  record "WARN" "P-25 Static AWS creds" "$count files use static AWS credentials (should use IAM roles)"
fi

secrets_mgr=$(grep -rn --include="*.java" \
  "SecretsManager\|getSecretValue\|secretsmanager\|ConfigurationManager" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$secrets_mgr" ]]; then
  record "PASS" "P-25 Secrets Manager" "AWS Secrets Manager integration found"
else
  record "WARN" "P-25 Secrets Manager" "No Secrets Manager usage found"
fi
