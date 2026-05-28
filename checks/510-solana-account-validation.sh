#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-510
name: Solana Anchor Account Validation
description: Detects Solana Anchor instructions whose Accounts struct lacks #[account(...)] constraints (mut, has_one, seeds, bump, address, owner). Missing constraints let the runtime accept arbitrary account inputs, leading to cross-program impersonation and state corruption.
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
frameworks: OWASP-SC-Top-10:2025:SC01, NIST-CSF:2.0:PR.AC, CWE:284
cwe: 284
false_positive_rate: high
performance_class: fast
origin: Anchor framework standard practice. Multiple Solana exploits (Cashio Mar 2022 $52M, Wormhole Solana Feb 2022 $320M) traced to insufficient account validation.
PRESTON_META

echo "P-510: Solana Account Validation"

SRC="${SOURCE_DIR:-.}"
anchor_files=$(grep -rln --include="*.rs" -E "use anchor_lang|#\[derive\(Accounts\)\]" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

if [[ -z "$anchor_files" ]]; then
  record "SKIP" "P-510 Solana account validation" "No Anchor framework usage detected"
  return 0 2>/dev/null || true
fi

unprotected=0
unprotected_list=""
for f in $anchor_files; do
  has_constraints=$(grep -cE '#\[account\(' "$f" 2>/dev/null || echo 0)
  has_accounts_struct=$(grep -cE '#\[derive\(Accounts\)\]' "$f" 2>/dev/null || echo 0)
  if [[ ${has_accounts_struct:-0} -gt 0 && ${has_constraints:-0} -eq 0 ]]; then
    ((unprotected++))
    unprotected_list+="$f"$'\n'
  fi
done

if [[ $unprotected -eq 0 ]]; then
  total=$(echo "$anchor_files" | wc -l | tr -d ' ')
  record "PASS" "P-510 Solana account validation" "$total Anchor file(s) all use #[account(...)] constraints"
else
  sample=$(printf '%s' "$unprotected_list" | head -10)
  record "FAIL" "P-510 Solana account validation" "$unprotected Anchor file(s) declare Accounts without #[account(...)] constraints" "$sample"
fi
