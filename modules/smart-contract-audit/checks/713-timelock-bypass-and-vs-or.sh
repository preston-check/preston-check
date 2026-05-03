#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-713
name: Timelock Bypass via && Instead of || Predicate
description: Detects high-value-or-multi-sig predicates that use logical AND where logical OR is required. The pattern `if (balance >= threshold && requiredApprovals > 1) revert ProposalNotReady();` lets a single-signer escrow execute high-value transactions WITHOUT going through the timelocked proposal path — the attacker only needs to remain a single-signer config. The correct predicate is OR: high-value OR multi-sig must always route through the proposal/timelock system.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.7.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02, CWE:863
cwe: 863
false_positive_rate: medium
performance_class: fast
origin: digital_escrow SwapEscrow SC-C1 (March 2026) — execute_swap_distribution() used `if (balance >= timelockThreshold && requiredApprovals > 1)` which let single-handler high-value escrows bypass the 24-hour timelock. Fixed by changing && to ||.
PRESTON_META

echo "P-713: Timelock Bypass — && vs || Predicate"

SRC="${SOURCE_DIR:-.}"
escrow_files=$(grep -rl --include="*.sol" -E 'timelockThreshold|TIMELOCK_PERIOD|MIN_DELAY|requiredApprovals|GOVERNANCE_DELAY' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$escrow_files" ]]; then
  record "SKIP" "P-713 Timelock bypass" "No timelock / multi-sig escrow contracts detected"
  return 0 2>/dev/null || true
fi

# Look for the bug pattern: threshold AND approvals (should be OR)
# This is a heuristic — flags any line that combines a threshold comparison with an approvals
# comparison via &&.
bad=""
for f in $escrow_files; do
  hits=$(grep -nE '(>=|>)\s*[A-Za-z_]*([Tt]hreshold|TIMELOCK|MIN_).*&&.*([Aa]pprovals|[Hh]andlers)' "$f" 2>/dev/null \
    | grep -vE '^\s*//' || true)
  if [[ -n "$hits" ]]; then
    bad="${bad}${f}: ${hits}"$'\n'
  fi
done
bad=$(echo "$bad" | sed '/^$/d')

e=$(echo "$escrow_files" | wc -l | tr -d ' ')
b=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-713 Timelock bypass" "$e timelocked file(s); no AND-vs-OR bypass pattern detected"
else
  record "FAIL" "P-713 Timelock bypass" "$b suspect predicate(s) combining threshold && approvals — should be OR" "$bad"
fi
