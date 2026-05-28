#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-514
name: Solana Cross-Program Invocation (CPI) Safety
description: Detects Solana CPI calls (invoke / invoke_signed) whose target program ID is not validated. Untyped CPI calls accept arbitrary downstream programs; without a program ID assertion, attackers can redirect CPI invocations to malicious programs.
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
frameworks: OWASP-SC-Top-10:2025:SC02, CWE:441
cwe: 441
false_positive_rate: medium
performance_class: fast
origin: Solana CPI safety is a recurring audit finding; recommended pattern is to assert the target program ID before invocation.
PRESTON_META

echo "P-514: Solana CPI Safety"

SRC="${SOURCE_DIR:-.}"
cpi_calls=$(grep -rln --include="*.rs" -E "\binvoke(_signed)?\s*\(|CpiContext::" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

if [[ -z "$cpi_calls" ]]; then
  record "SKIP" "P-514 Solana CPI safety" "No CPI invocations detected"
  return 0 2>/dev/null || true
fi

program_check=$(grep -rln --include="*.rs" -E "program_id\s*==|require_keys_eq|address\s*=\s*[A-Za-z_]+::ID|#\[account\(\s*address\s*=" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

c_count=$(echo "$cpi_calls" | wc -l | tr -d ' ')
pc_count=$([[ -n "$program_check" ]] && echo "$program_check" | wc -l | tr -d ' ' || echo 0)

if [[ ${pc_count:-0} -eq 0 ]]; then
  record "WARN" "P-514 Solana CPI safety" "$c_count file(s) make CPI calls without observable target program ID validation" "$(echo "$cpi_calls" | head -10)"
else
  record "PASS" "P-514 Solana CPI safety" "$c_count file(s) make CPI calls; $pc_count file(s) validate program IDs"
fi
