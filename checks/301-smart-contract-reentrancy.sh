#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-301
name: Smart Contract Reentrancy Protection
description: Detects Solidity contracts that make external calls (.call, .send, .transfer with value) in functions lacking nonReentrant modifiers or proper checks-effects-interactions ordering. Reentrancy is the root cause of many of the largest DeFi exploits (The DAO 2016, Cream Finance 2021, Fei Protocol 2022).
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC05, NIST-SSDF:1.1:PW.7
cwe: 841
false_positive_rate: medium
performance_class: fast
origin: The DAO hack (2016) drained $60M via recursive call exploitation. Has remained the #1 root cause of major DeFi exploits for nearly a decade.
PRESTON_META

echo "P-301: Smart Contract Reentrancy Protection"

SRC="${SOURCE_DIR:-.}"
sol_count=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/test/*" -not -path "*/tests/*" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$sol_count" -eq 0 ]]; then
  record "SKIP" "P-301 Reentrancy" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

external_call_files=$(grep -rl --include="*.sol" -E '\.call\{value:|\.send\(|address\(.*\)\.transfer\(' --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -v "/test/\|/tests/\|/mock/\|node_modules" || true)

if [[ -z "$external_call_files" ]]; then
  record "PASS" "P-301 Reentrancy" "No risky external value transfers found in contracts"
  return 0 2>/dev/null || true
fi

unsafe=0
for f in $external_call_files; do
  if ! grep -qE 'nonReentrant|ReentrancyGuard|locked.*=.*true|_status.*=.*ENTERED' "$f" 2>/dev/null; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-301 Reentrancy" "All contracts with external calls use nonReentrant or equivalent guards"
else
  record "FAIL" "P-301 Reentrancy" "$unsafe Solidity contract(s) make external value transfers without nonReentrant modifier" "$(echo "$external_call_files" | head -10)"
fi
