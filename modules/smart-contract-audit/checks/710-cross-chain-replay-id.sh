#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-710
name: Cross-Chain Replay in HTLC / Escrow IDs
description: Detects HTLC and escrow-style contracts that derive identifiers (htlcId, swapId, salt) without binding block.chainid and address(this). Without these binders, an identifier minted on chain A can be replayed against an identical contract address on chain B (or against a fork), enabling double-claim attacks on bridged or multi-chain deployments.
category: code-scan
severity: high
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.7.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC03, CWE:294
cwe: 294
false_positive_rate: medium
performance_class: fast
origin: Pattern surfaced in the digital_escrow HTLC final audit (Feb 2026, §1.6) — the production fix binds chainid + address(this) into _generateId() to make IDs unforgeable across chains and forks.
PRESTON_META

echo "P-710: Cross-Chain Replay in HTLC / Escrow IDs"

SRC="${SOURCE_DIR:-.}"
htlc_files=$(grep -rl --include="*.sol" -E '\b(hashLock|preimage|HTLC|htlcId|atomic\s*swap|secret\s*hash)\b' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$htlc_files" ]]; then
  record "SKIP" "P-710 Cross-chain replay" "No HTLC / atomic-swap contracts detected"
  return 0 2>/dev/null || true
fi

unbound=""
for f in $htlc_files; do
  has_id_gen=$(grep -cE 'keccak256\s*\(\s*abi\.(encode|encodePacked)\s*\(' "$f" 2>/dev/null)
  has_chainid=$(grep -cE 'block\.chainid' "$f" 2>/dev/null)
  has_self=$(grep -cE 'address\(\s*this\s*\)' "$f" 2>/dev/null)
  if [[ ${has_id_gen:-0} -gt 0 ]] && { [[ ${has_chainid:-0} -eq 0 ]] || [[ ${has_self:-0} -eq 0 ]]; }; then
    unbound="${unbound}${f}"$'\n'
  fi
done
unbound=$(echo "$unbound" | sed '/^$/d')

h=$(echo "$htlc_files" | wc -l | tr -d ' ')
u=$([[ -n "$unbound" ]] && echo "$unbound" | wc -l | tr -d ' ' || echo 0)

if [[ ${u:-0} -eq 0 ]]; then
  record "PASS" "P-710 Cross-chain replay" "$h HTLC file(s); ID derivation binds chainid + address(this)"
else
  record "FAIL" "P-710 Cross-chain replay" "$u of $h HTLC file(s) generate IDs without block.chainid or address(this) binding" "$unbound"
fi
