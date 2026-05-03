#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-349
name: EIP-2612 Permit Replay Protection
description: Verifies that ERC-20 Permit (EIP-2612) implementations and consumers correctly handle nonces, deadlines, and chain ID to prevent signature replay across chains or after a permit has already been consumed. Permit signatures bypass on-chain approval and are a common phishing target — consumers must validate nonces and deadlines before submitting.
category: code-scan
severity: high
languages: solidity, typescript, javascript
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02
cwe: 294
false_positive_rate: medium
performance_class: fast
origin: Permit-based phishing (gasless approvals via signed messages) is heavily exploited by drainer kits; protocol-level replay protection is essential.
PRESTON_META

echo "P-349: EIP-2612 Permit Replay"

SRC="${SOURCE_DIR:-.}"

permit_files=$(grep -rl --include="*.sol" --include="*.ts" --include="*.js" \
  -iE 'permit\s*\(|signPermit|EIP-?2612|EIP_?2612|DOMAIN_SEPARATOR' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$permit_files" ]]; then
  record "SKIP" "P-349 Permit replay" "No EIP-2612 Permit usage detected"
  return 0 2>/dev/null || true
fi

unsafe=0
total=0
for f in $permit_files; do
  ((total++))
  has_nonce=$(grep -cE 'nonces\[|_useNonce|nonces\s*\(\s*owner\)|usedNonces' "$f" 2>/dev/null || echo 0)
  has_deadline=$(grep -cE 'deadline\s*[><=]|block\.timestamp\s*[<>=]\s*deadline|require[^)]*deadline' "$f" 2>/dev/null || echo 0)
  has_chainid=$(grep -cE 'block\.chainid|chainId\s*\(\s*\)|DOMAIN_SEPARATOR' "$f" 2>/dev/null || echo 0)
  if [[ ${has_nonce:-0} -eq 0 || ${has_deadline:-0} -eq 0 || ${has_chainid:-0} -eq 0 ]]; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-349 Permit replay" "$total permit-using file(s) include nonce, deadline, and chain-ID handling"
else
  record "FAIL" "P-349 Permit replay" "$unsafe of $total permit-using file(s) lack nonce/deadline/chainId enforcement"
fi
