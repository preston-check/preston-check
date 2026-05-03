#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-312
name: HSM Integration for Production Signing
description: Verifies that production transaction signing references a hardware security module (HSM) or KMS-backed signing path rather than software-loaded keys. Software keys live in process memory and are exposed to memory-scraping malware, container escapes, and insider extraction; HSM-backed signing reduces blast radius.
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
frameworks: NIST-CSF:2.0:PR.DS, ISO-27001:2022:A.10.1
cwe: 320
false_positive_rate: high
performance_class: fast
origin: Multiple exchange compromises (e.g., 2018 Coincheck $530M loss) traced back to hot wallets backed by software keys with no HSM segregation.
PRESTON_META

echo "P-312: HSM Integration"

SRC="${SOURCE_DIR:-.}"

# Find code paths that perform signing
sign_calls=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'signTransaction|signMessage|wallet\.sign|ecdsa.*sign|secp256k1.*sign|signTx|sendRawTransaction|createSignature' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/tests/|/spec/|node_modules|/mock|/example' || true)

if [[ -z "$sign_calls" ]]; then
  record "SKIP" "P-312 HSM integration" "No transaction-signing code paths detected"
  return 0 2>/dev/null || true
fi

# Look for HSM/KMS/Vault references
hsm_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'cloudHSM|YubiHSM|nCipher|pkcs11|fireblocks|kms\.|KMSClient|AwsKmsSigner|GoogleKmsSigner|Tink|HashiCorpVault|VaultClient|hcvault|secretsManager|SecretsManagerSigner' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/tests/|/spec/|node_modules|/mock' || true)

if [[ -z "$hsm_refs" ]]; then
  record "FAIL" "P-312 HSM integration" "Transaction signing detected but no HSM/KMS/Vault integration found" "$(echo "$hsm_refs" | head -10)"
else
  hsm_count=$(echo "$hsm_refs" | wc -l | tr -d ' ')
  record "PASS" "P-312 HSM integration" "$hsm_count file(s) reference HSM/KMS/Vault-backed signing"
fi
