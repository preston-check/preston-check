#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-511
name: Solana Signer Verification
description: Detects Solana Anchor instructions that mutate state without verifying the originating account is a Signer. Solana programs that don't enforce signer requirements on privileged operations allow any caller to invoke them with arbitrary account references.
category: code-scan
severity: critical
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
false_positive_rate: high
performance_class: fast
origin: Solana program-security audits consistently surface missing Signer checks; one of the top three Solana-specific vulnerability classes.
PRESTON_META

echo "P-511: Solana Signer Verification"

SRC="${SOURCE_DIR:-.}"
solana_files=$(grep -rln --include="*.rs" -E "use anchor_lang|use solana_program" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

if [[ -z "$solana_files" ]]; then
  record "SKIP" "P-511 Solana signer verification" "No Solana programs detected"
  return 0 2>/dev/null || true
fi

# Check for Signer<'info> use or is_signer assertions
signer_use=$(grep -rln --include="*.rs" -E "Signer<|is_signer|has_one\s*=\s*authority" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/target/" || true)

s_count=$([[ -n "$signer_use" ]] && echo "$signer_use" | wc -l | tr -d ' ' || echo 0)
total=$(echo "$solana_files" | wc -l | tr -d ' ')

if [[ ${s_count:-0} -eq 0 ]]; then
  record "FAIL" "P-511 Solana signer verification" "$total Solana program file(s) without Signer<> or is_signer enforcement" "$(echo "$solana_files" | head -10)"
else
  record "PASS" "P-511 Solana signer verification" "$s_count of $total Solana file(s) reference Signer<>/is_signer"
fi
