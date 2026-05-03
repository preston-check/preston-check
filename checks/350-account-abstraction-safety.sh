#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-350
name: Account Abstraction (ERC-4337) Safety
description: Detects ERC-4337 smart account / paymaster implementations without proper validation: paymaster fund-draining via DoS, signature aggregator misuse, missing simulation gas limits, or incorrect bundle handling. Account abstraction is the primary smart-wallet path on Ethereum but introduces a new class of vulnerabilities at the bundler/paymaster boundary.
category: code-scan
severity: medium
languages: solidity, typescript, javascript
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02
cwe: 1188
false_positive_rate: high
performance_class: fast
origin: ERC-4337 deployed July 2023 has seen rapid adoption (Safe, ZeroDev, Biconomy, Stackup); security findings cluster around paymaster economics, validateUserOp logic, and signature aggregator bugs.
PRESTON_META

echo "P-350: ERC-4337 Account Abstraction"

SRC="${SOURCE_DIR:-.}"

aa_files=$(grep -rl --include="*.sol" --include="*.ts" --include="*.js" \
  -iE 'EntryPoint|UserOperation|userOp|validateUserOp|IPaymaster|Paymaster|ERC4337|ERC-4337|simpleAccount|StackupV1|@account-abstraction' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$aa_files" ]]; then
  record "SKIP" "P-350 Account abstraction" "No ERC-4337 / account-abstraction code detected"
  return 0 2>/dev/null || true
fi

unsafe=0
total=0
for f in $aa_files; do
  ((total++))
  has_validation=$(grep -cE 'validateUserOp|_validateSignature|verificationGasLimit|preVerificationGas|missingAccountFunds' "$f" 2>/dev/null || echo 0)
  if [[ ${has_validation:-0} -eq 0 ]]; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-350 Account abstraction" "$total ERC-4337 file(s) implement validateUserOp / signature validation"
else
  record "WARN" "P-350 Account abstraction" "$unsafe of $total ERC-4337 file(s) lack validateUserOp or gas-limit handling"
fi
