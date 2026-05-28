#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-515
name: Solana Lamport Drain / Realloc Safety
description: Detects Solana account-mutation patterns that could drain lamports or shrink account data without rent-exempt verification. Reallocating an account smaller than its rent-exempt threshold causes the runtime to free its data and lamports.
category: code-scan
severity: medium
languages: rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.4.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04, CWE:691
cwe: 691
false_positive_rate: high
performance_class: fast
origin: Solana account model edge cases — lamport accounting and realloc semantics are uncommonly understood and surface in audits as a recurring class.
PRESTON_META

echo "P-515: Solana Lamport Drain Safety"

SRC="${SOURCE_DIR:-.}"
lamport_ops=$(grep -rln --include="*.rs" -E "\.lamports|realloc\s*\(|try_borrow_mut_lamports" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

if [[ -z "$lamport_ops" ]]; then
  record "SKIP" "P-515 Solana lamport drain" "No lamport / realloc operations detected"
  return 0 2>/dev/null || true
fi

rent_check=$(grep -rln --include="*.rs" -E "Rent::|is_exempt|rent_exempt|minimum_balance" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

l_count=$(echo "$lamport_ops" | wc -l | tr -d ' ')
r_count=$([[ -n "$rent_check" ]] && echo "$rent_check" | wc -l | tr -d ' ' || echo 0)

if [[ ${r_count:-0} -eq 0 ]]; then
  record "WARN" "P-515 Solana lamport drain" "$l_count file(s) manipulate lamports without rent-exempt verification" "$(echo "$lamport_ops" | head -10)"
else
  record "PASS" "P-515 Solana lamport drain" "$l_count file(s) manipulate lamports; $r_count file(s) check rent exemption"
fi
