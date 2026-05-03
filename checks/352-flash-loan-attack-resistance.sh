#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-352
name: Flash Loan Attack Resistance
description: Detects smart contract logic vulnerable to flash-loan-induced price or governance manipulation: state-dependent decisions on spot prices, governance vote-counting based on current balances, single-block-sensitive computations. Flash loan attacks were a $33.8M loss category in 2025 (OWASP SC Top 10).
category: code-scan
severity: high
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04
cwe: 1188
false_positive_rate: high
performance_class: fast
origin: bZx, Cream Finance, Beanstalk, Mango Markets, GMX July 2025 — all involved flash loans manipulating governance or prices within a single block.
PRESTON_META

echo "P-352: Flash Loan Attack Resistance"

SRC="${SOURCE_DIR:-.}"
sol_files=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/test/*" 2>/dev/null)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-352 Flash loan resistance" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

# Find governance/voting functions using current balanceOf
unsafe_voting=$(grep -rl --include="*.sol" \
  -E 'function\s+(vote|propose|delegateBy|getVotes|getCurrentVotes)\s*\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' \
  | xargs grep -l -E 'balanceOf\s*\(' 2>/dev/null \
  | xargs grep -L -E 'snapshot|getPastVotes|checkpoint|pastBalance' 2>/dev/null || true)

# Find pricing logic that depends on getReserves/balanceOf without snapshot
flash_resist=$(grep -rln --include="*.sol" \
  -iE 'flashLoanProtection|notFlashLoan|sameBlockGuard|nonFlashLoan|reentrancyAndFlashLoan|cumulativePrice|TWAP|consult\(|getTimeWeighted' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

unsafe_count=$([[ -n "$unsafe_voting" ]] && echo "$unsafe_voting" | wc -l | tr -d ' ' || echo 0)

if [[ ${unsafe_count:-0} -gt 0 ]]; then
  record "FAIL" "P-352 Flash loan resistance" "$unsafe_count voting/governance contract(s) read live balanceOf without snapshot/checkpoint protection"
elif [[ -z "$flash_resist" ]]; then
  record "WARN" "P-352 Flash loan resistance" "No flash-loan-resistance patterns detected; consider TWAP, snapshots, or same-block guards"
else
  count=$(echo "$flash_resist" | wc -l | tr -d ' ')
  record "PASS" "P-352 Flash loan resistance" "$count file(s) reference flash-loan resistance patterns"
fi
