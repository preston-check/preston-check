#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-303
name: tx.origin Authorization Anti-Pattern
description: Detects Solidity contracts using tx.origin for authorization checks instead of msg.sender. tx.origin is always the EOA that initiated the transaction, so contracts trusting it are vulnerable to phishing-via-malicious-contract attacks where a victim is tricked into calling an attacker contract that then calls the victim contract on their behalf.
category: code-scan
severity: high
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02, CWE:284
cwe: 284
false_positive_rate: low
performance_class: fast
origin: Vitalik Buterin's 2016 warning about tx.origin authorization. Still surfaces in audits as a beginner mistake; always severe when present.
PRESTON_META

echo "P-303: tx.origin Authorization"

SRC="${SOURCE_DIR:-.}"
sol_count=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$sol_count" -eq 0 ]]; then
  record "SKIP" "P-303 tx.origin auth" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

hits=$(grep -rn --include="*.sol" -E 'require\s*\(\s*tx\.origin|if\s*\(\s*tx\.origin|tx\.origin\s*==' --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -v "/test/\|/mock/\|node_modules" \
  | grep -v "tx.origin != tx.origin" || true)

if [[ -z "$hits" ]]; then
  record "PASS" "P-303 tx.origin auth" "No tx.origin used for authorization"
else
  count=$(echo "$hits" | wc -l | tr -d ' ')
  sample=$(echo "$hits" | head -10)
  record "FAIL" "P-303 tx.origin auth" "$count line(s) use tx.origin for authorization checks" "$sample"
fi
