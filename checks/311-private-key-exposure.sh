#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-311
name: Private Key / Mnemonic Exposure
description: Detects hardcoded private keys (64-hex), BIP-39 mnemonic phrases (12 or 24 words from the wordlist), or PRIVATE_KEY/MNEMONIC env-var assignments outside .env.example or test fixtures. Crypto private keys in source control are catastrophic and irreversible.
category: code-scan
severity: critical
languages: solidity, typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:3.5, OWASP-API:2023:API8, CWE:798
cwe: 798, 312
false_positive_rate: medium
performance_class: medium
origin: Multiple major crypto exchange and DeFi project incidents involved committed-to-git private keys discovered by scanning bots within minutes of push.
PRESTON_META

echo "P-311: Private Key / Mnemonic Exposure"

SRC="${SOURCE_DIR:-.}"

# 64-hex private keys assigned to a variable
hex_keys=$(grep -rnE --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.sol" \
  --include="*.json" --include="*.yml" --include="*.yaml" --include="*.env" \
  '(privateKey|PRIVATE_KEY|priv_key|privKey|secret_key)\s*[=:]\s*["'\''](0x)?[a-fA-F0-9]{64}["'\'']' "$SRC" 2>/dev/null \
  | grep -vE '\.example|/test/|/tests/|/spec/|node_modules|/mock|fixture|0x[0]{64}' || true)

# BIP-39 mnemonic detection: 12 or 24 lowercase words, comma or space separated
mnemonic_hits=$(grep -rnE --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.json" \
  --include="*.yml" --include="*.yaml" --include="*.env" \
  '(mnemonic|MNEMONIC|seed_phrase|seedPhrase|recovery_phrase)\s*[=:]\s*["'\''][a-z]+(\s+[a-z]+){11,}["'\'']' "$SRC" 2>/dev/null \
  | grep -vE '\.example|/test/|/tests/|/spec/|node_modules|/mock|fixture' || true)

# Env-var declarations with values (not just refs)
env_assignments=$(grep -rnE --include="*.env" --include=".env*" --include="*.sh" --include="Dockerfile*" \
  '^(PRIVATE_KEY|MNEMONIC|WALLET_KEY|WALLET_SEED)\s*=\s*[^$]' "$SRC" 2>/dev/null \
  | grep -vE '\.example|/test/' || true)

count=0
[[ -n "$hex_keys" ]]         && count=$((count + $(echo "$hex_keys" | wc -l | tr -d ' ')))
[[ -n "$mnemonic_hits" ]]    && count=$((count + $(echo "$mnemonic_hits" | wc -l | tr -d ' ')))
[[ -n "$env_assignments" ]]  && count=$((count + $(echo "$env_assignments" | wc -l | tr -d ' ')))

if [[ $count -eq 0 ]]; then
  record "PASS" "P-311 Private key exposure" "No hardcoded private keys, mnemonics, or wallet seed env values found"
else
  all=""
  [[ -n "$hex_keys" ]]        && all+="$hex_keys"$'\n'
  [[ -n "$mnemonic_hits" ]]   && all+="$mnemonic_hits"$'\n'
  [[ -n "$env_assignments" ]] && all+="$env_assignments"$'\n'
  sample=$(printf '%s' "$all" | head -10)
  record "FAIL" "P-311 Private key exposure" "$count exposed private-key/mnemonic pattern(s) found in source — ROTATE IMMEDIATELY" "$sample"
fi
