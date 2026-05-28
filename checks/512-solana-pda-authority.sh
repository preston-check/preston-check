#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-512
name: Solana PDA Authority Validation
description: Detects Solana Program-Derived Addresses (PDAs) used as authorities without #[account(seeds = ..., bump)] derivation constraints. PDAs whose derivation isn't validated can be substituted by attacker-controlled accounts, defeating the authority pattern.
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
origin: PDA authority bypass is a documented Solana attack pattern; Cashio (Mar 2022, $52M) was a prominent example.
PRESTON_META

echo "P-512: Solana PDA Authority Validation"

SRC="${SOURCE_DIR:-.}"
pda_files=$(grep -rln --include="*.rs" -E "find_program_address|create_program_address|Pubkey::find_program_address" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

if [[ -z "$pda_files" ]]; then
  record "SKIP" "P-512 Solana PDA authority" "No PDA derivation detected"
  return 0 2>/dev/null || true
fi

seeds_constraint=$(grep -rln --include="*.rs" -E "seeds\s*=\s*\[|bump\s*[:=]\s*[a-zA-Z_]" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

p_count=$(echo "$pda_files" | wc -l | tr -d ' ')
sc_count=$([[ -n "$seeds_constraint" ]] && echo "$seeds_constraint" | wc -l | tr -d ' ' || echo 0)

if [[ ${sc_count:-0} -eq 0 ]]; then
  record "WARN" "P-512 Solana PDA authority" "$p_count file(s) derive PDAs without observable seeds/bump constraints" "$(echo "$pda_files" | head -10)"
else
  record "PASS" "P-512 Solana PDA authority" "$p_count file(s) derive PDAs; $sc_count file(s) reference seeds/bump constraints"
fi
