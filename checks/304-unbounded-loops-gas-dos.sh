#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-304
name: Unbounded Loops / Gas DoS
description: Detects Solidity for/while loops that iterate over user-controlled or unbounded arrays. These can be exploited as DoS by adversaries adding entries until the loop exceeds the block gas limit, permanently bricking the function.
category: code-scan
severity: medium
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC09
cwe: 400
false_positive_rate: high
performance_class: fast
origin: GovernMental Ponzi (2016) became permanently stuck because its withdrawal loop exceeded gas limits. The pattern recurs in airdrop/distribution contracts.
PRESTON_META

echo "P-304: Unbounded Loops"

SRC="${SOURCE_DIR:-.}"
sol_files=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/test/*" 2>/dev/null)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-304 Unbounded loops" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

# Heuristic: for/while loops bounded by .length on storage arrays without explicit caps
suspicious=$(grep -rn --include="*.sol" -E 'for\s*\(\s*uint[^;]*;\s*[a-zA-Z_]+\s*<\s*[a-zA-Z_]+\.length\s*;|while\s*\(\s*[a-zA-Z_]+\.length' "$SRC" 2>/dev/null \
  | grep -v "/test/\|node_modules" \
  | grep -vE 'MAX_|MAXIMUM_|uint8|uint16' || true)

if [[ -z "$suspicious" ]]; then
  record "PASS" "P-304 Unbounded loops" "No suspicious unbounded loop patterns found"
else
  count=$(echo "$suspicious" | wc -l | tr -d ' ')
  record "WARN" "P-304 Unbounded loops" "$count loop(s) iterate over .length without explicit bounds — review for DoS"
fi
