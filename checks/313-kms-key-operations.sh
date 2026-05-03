#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-313
name: KMS-Only Key Operations
description: Detects code that loads private keys from environment variables, files, or string literals instead of through a managed KMS (AWS KMS, GCP KMS, Azure Key Vault). Keys read into application memory cross multiple trust boundaries (process memory, container, host) compared to KMS operations that never expose the raw key material to the application.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, ISO-27001:2022:A.10.1, PCI-DSS:4.0:3.6
cwe: 312
false_positive_rate: medium
performance_class: fast
origin: Insider-threat and runtime-compromise scenarios where keys held in process memory were extracted via memory dumps or core files; common in cloud post-incident reviews.
PRESTON_META

echo "P-313: KMS-Only Key Operations"

SRC="${SOURCE_DIR:-.}"

# Detect raw key loads
env_key_loads=$(grep -rnE --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  'process\.env\.PRIVATE_KEY|os\.getenv\s*\(\s*["'\''](PRIVATE_KEY|WALLET_KEY|SIGNING_KEY)|System\.getenv\s*\(\s*["'\''](PRIVATE_KEY|SIGNING_KEY)|env::var\s*\(\s*["'\''](PRIVATE_KEY|SIGNING_KEY)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/tests/|/spec/|node_modules|/mock' || true)

file_key_loads=$(grep -rnE --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  'readFileSync\s*\([^)]*\.pem|readFile\s*\([^)]*\.pem|Files\.readAllBytes\s*\([^)]*key.*\.pem|open\s*\([^)]*\.pem|\.json["'\'']\s*\)\.privateKey|JSON\.parse[^)]*privateKey' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/tests/|/spec/|node_modules|/mock|wallet.*public' || true)

unsafe_count=0
[[ -n "$env_key_loads" ]]  && unsafe_count=$((unsafe_count + $(echo "$env_key_loads" | wc -l | tr -d ' ')))
[[ -n "$file_key_loads" ]] && unsafe_count=$((unsafe_count + $(echo "$file_key_loads" | wc -l | tr -d ' ')))

# KMS references
kms_count=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'kms\.|KMSClient|aws-sdk.*KMS|@google-cloud/kms|@azure/keyvault|crypto/kms|HashicorpVault|VaultSigner|sign\s*\(\s*\{\s*KeyId' "$SRC" 2>/dev/null \
  | grep -vE '/test/|node_modules' | wc -l | tr -d ' ')

if [[ $unsafe_count -eq 0 ]]; then
  record "PASS" "P-313 KMS key ops" "No raw private-key loading detected; ${kms_count:-0} KMS reference(s) present"
elif [[ ${kms_count:-0} -gt 0 ]]; then
  record "WARN" "P-313 KMS key ops" "$unsafe_count raw key load(s) co-exist with $kms_count KMS reference(s); confirm raw loads are dev-only" "$(echo "$kms_count" | head -10)"
else
  record "FAIL" "P-313 KMS key ops" "$unsafe_count raw private-key load path(s) without any KMS integration" "$(echo "$kms_count" | head -10)"
fi
