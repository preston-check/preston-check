#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-353
name: Unchecked External Call Returns (OWASP SC7:2025)
description: Detects Solidity .call() invocations whose return value is not checked. .call() returns (bool success, bytes memory data) and silently swallows failure when the boolean is ignored — funds appear to move while state diverges from on-chain reality.
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
frameworks: OWASP-SC-Top-10:2025:SC07, CWE:252
cwe: 252
false_positive_rate: medium
performance_class: fast
origin: OWASP SC Top 10 (2025) tracked $550K+ in confirmed losses traceable to unchecked .call() returns; the actual loss is likely higher because silent failures often go unattributed.
PRESTON_META

echo "P-353: Unchecked External Call Returns"

SRC="${SOURCE_DIR:-.}"
sol_files=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/test/*" 2>/dev/null)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-353 Unchecked calls" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

# Pattern: .call(...) without capturing/checking the bool return
# Heuristic: lines with .call but neither (bool|success) =, require, nor assert
suspicious=$(grep -rn --include="*.sol" -E '\.call\{value:|\.call\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' \
  | grep -vE '(bool\s+\w+\s*,?|\(\s*bool|success\s*,|require\s*\(|assert\s*\(|\.call\.value)' || true)

if [[ -z "$suspicious" ]]; then
  record "PASS" "P-353 Unchecked calls" "All low-level .call invocations check the return value"
else
  count=$(echo "$suspicious" | wc -l | tr -d ' ')
  record "FAIL" "P-353 Unchecked calls" "$count line(s) call .call() without checking the success return"
fi
