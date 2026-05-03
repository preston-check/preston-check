#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-718
name: Untrusted bytes Storage Without Length Cap
description: Detects functions that accept `bytes calldata` from external callers and write the data directly to storage without an explicit length bound. An attacker can cheaply pay deployment-time SSTORE costs to write multi-megabyte payloads, exhausting contract memory budgets and bricking later operations that read or copy the same slot. Every persisted bytes parameter should have a require(_data.length <= MAX_*) guard, with MAX_* an immutable or owner-tunable constant.
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
frameworks: OWASP-SC-Top-10:2025:SC09, CWE:1284
cwe: 1284
false_positive_rate: medium
performance_class: fast
origin: digital_escrow MPCShardStorage M-6 (March 2026) — storeShard accepted bytes calldata. Fix introduced maxShardSize (default 10 KB, owner-tunable 1 KB–100 KB) with a require check before SSTORE, plus a per-keyId shard count cap and pausability.
PRESTON_META

echo "P-718: Untrusted bytes Storage Without Length Cap"

SRC="${SOURCE_DIR:-.}"
sol_files=$(grep -rl --include="*.sol" -E 'bytes\s+calldata\b|bytes\s+memory\b' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-718 bytes length cap" "No bytes-parameter contracts detected"
  return 0 2>/dev/null || true
fi

# Heuristic: file accepts bytes calldata in an external function AND assigns/stores it
# (encryptedData =, .data =, push(_data)) with no length-bound check anywhere.
bad=""
for f in $sol_files; do
  has_bytes_param=$(grep -cE 'bytes\s+calldata\s+_?[A-Za-z]' "$f" 2>/dev/null)
  has_storage_assign=$(grep -cE '\.encryptedData\s*=|\.data\s*=\s*_?[A-Za-z]+\s*;|=\s*_?[A-Za-z]+Data\s*;' "$f" 2>/dev/null)
  has_length_cap=$(grep -cE 'length\s*<=?\s*[A-Za-z_]+|require\s*\([^)]*length\s*<' "$f" 2>/dev/null)
  if [[ ${has_bytes_param:-0} -gt 0 && ${has_storage_assign:-0} -gt 0 && ${has_length_cap:-0} -eq 0 ]]; then
    bad="${bad}${f}"$'\n'
  fi
done
bad=$(echo "$bad" | sed '/^$/d')

s=$(echo "$sol_files" | wc -l | tr -d ' ')
b=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-718 bytes length cap" "$s bytes-bearing file(s); length caps present or no storage assignment"
else
  record "WARN" "P-718 bytes length cap" "$b file(s) store bytes calldata without an explicit length cap" "$bad"
fi
