#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-513
name: Solana Account Owner Verification
description: Detects Solana programs that operate on accounts without verifying the program ID owns them. Account-owner spoofing (substituting a fake-but-similar account from a different program) is a recurring exploit class on Solana.
category: code-scan
severity: high
languages: rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.4.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02, NIST-CSF:2.0:PR.AC, CWE:284
cwe: 284
false_positive_rate: medium
performance_class: fast
origin: Account confusion / type confusion attacks on Solana have caused multiple exploits; Anchor's #[account(owner = ...)] constraint is the canonical defense.
PRESTON_META

echo "P-513: Solana Account Owner Verification"

SRC="${SOURCE_DIR:-.}"
solana_files=$(grep -rln --include="*.rs" -E "use anchor_lang|use solana_program::account_info" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

if [[ -z "$solana_files" ]]; then
  record "SKIP" "P-513 Solana owner check" "No Solana programs detected"
  return 0 2>/dev/null || true
fi

owner_check=$(grep -rln --include="*.rs" -E "owner\s*=\s*|account_info\.owner|\.owner\s*==" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

t_count=$(echo "$solana_files" | wc -l | tr -d ' ')
o_count=$([[ -n "$owner_check" ]] && echo "$owner_check" | wc -l | tr -d ' ' || echo 0)

if [[ ${o_count:-0} -eq 0 ]]; then
  record "WARN" "P-513 Solana owner check" "$t_count Solana file(s) without observable account-owner verification" "$(echo "$solana_files" | head -10)"
else
  record "PASS" "P-513 Solana owner check" "$o_count of $t_count Solana file(s) verify account ownership"
fi
