#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-717
name: keccak256 abi.encodePacked Collision Risk
description: Detects keccak256(abi.encodePacked(...)) calls that include two or more variable-length types (string, bytes, dynamic arrays). encodePacked concatenates without delimiters, so for example abi.encodePacked("a", "bc") and abi.encodePacked("ab", "c") produce identical bytes — and therefore identical hashes. When the hash is used for an ID, signature, or commitment, this enables forgery. Use abi.encode (which length-prefixes) for any hash input that mixes variable-length types.
category: code-scan
severity: medium
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.7.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC03, CWE:328
cwe: 328
false_positive_rate: high
performance_class: fast
origin: SWC-133 / digital_escrow HTLC final audit (Feb 2026, §7.4) — explicitly verified that the production ID uses fixed-length-only inputs to abi.encodePacked and would be migrated to abi.encode if string keyId were added.
PRESTON_META

echo "P-717: keccak256 abi.encodePacked Collision Risk"

SRC="${SOURCE_DIR:-.}"
sol_files=$(grep -rl --include="*.sol" -E 'abi\.encodePacked\s*\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-717 encodePacked collision" "No abi.encodePacked usage detected"
  return 0 2>/dev/null || true
fi

# Heuristic: look for keccak256(abi.encodePacked(...)) with at least 2 'string' or 'bytes' or 'dynamic'
# parameters in the same expression. We approximate by scanning the line + next line.
bad=""
for f in $sol_files; do
  hits=$(grep -nE 'keccak256\s*\(\s*abi\.encodePacked\s*\(.*(string|bytes\b|\[\s*\])' "$f" 2>/dev/null \
    | grep -vE '^\s*//' || true)
  if [[ -n "$hits" ]]; then
    bad="${bad}${f}: ${hits}"$'\n'
  fi
done
bad=$(echo "$bad" | sed '/^$/d')

s=$(echo "$sol_files" | wc -l | tr -d ' ')
b=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-717 encodePacked collision" "$s file(s); no risky encodePacked patterns detected"
else
  record "WARN" "P-717 encodePacked collision" "$b file(s) hash variable-length data with abi.encodePacked — prefer abi.encode" "$bad"
fi
