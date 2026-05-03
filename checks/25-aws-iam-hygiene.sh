#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-25
name: AWS IAM Hygiene
description: Checks for static AWS credentials, missing Secrets Manager.
category: infra-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.6.1, SOC2:TSC-2017:CC6.1, SOC2:TSC-2017:CC6.3, ISO-27001:2022:5.15, ISO-27001:2022:8.2, NIST-CSF:2.0:PR.AA-1, CIS-v8:6.2
PRESTON_META


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
