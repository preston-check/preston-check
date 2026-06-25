#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-25
name: AWS IAM Hygiene
description: Checks for static AWS credentials, missing Secrets Manager.
category: infra-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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
  record "WARN" "P-25 Static AWS creds" "$count files use static AWS credentials (should use IAM roles)" "$(echo "$static_creds" | head -10)"
fi

secrets_mgr=$(grep -rn --include="*.java" \
  "SecretsManager\|getSecretValue\|secretsmanager\|ConfigurationManager" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$secrets_mgr" ]]; then
  record "PASS" "P-25 Secrets Manager" "AWS Secrets Manager integration found"
else
  record "WARN" "P-25 Secrets Manager" "No Secrets Manager usage found" "$(echo "$secrets_mgr" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "aws\.NewStaticCredentials|StaticCredentialsProvider|credentials\.NewStatic" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-25 Static AWS credentials (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-25 Static AWS credentials (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "rusoto_credential|StaticProvider|AwsCredentials::new" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-25 Static AWS credentials (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-25 Static AWS credentials (Rust)" "No issues found in Rust files"
  fi
fi
