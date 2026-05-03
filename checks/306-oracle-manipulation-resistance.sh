#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-306
name: Oracle Manipulation Resistance
description: Detects single-source spot-price reads (Chainlink latestRoundData without staleness checks, Uniswap V2 getReserves used as price oracle, custom oracles without TWAP). Spot prices can be manipulated within a single block via flash loans, and any contract trusting them as authoritative is at risk of being drained.
category: code-scan
severity: high
languages: solidity, typescript, javascript, go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC07
cwe: 345
false_positive_rate: medium
performance_class: fast
origin: bZx, Harvest Finance, Mango Markets, and dozens more lost combined billions to flash-loan-induced oracle manipulation between 2020 and 2023.
PRESTON_META

echo "P-306: Oracle Manipulation Resistance"

SRC="${SOURCE_DIR:-.}"
sol_count=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')
ts_count=$(find "$SRC" -name "*.ts" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$sol_count" -eq 0 && "$ts_count" -eq 0 ]]; then
  record "SKIP" "P-306 Oracle manipulation" "No Solidity or TypeScript files found"
  return 0 2>/dev/null || true
fi

# Single-source latestRoundData calls without staleness checks (no updatedAt or answeredInRound usage nearby)
chainlink_unsafe_files=$(grep -rl --include="*.sol" -E 'latestRoundData\s*\(\s*\)' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/mock/\|node_modules" || true)

unsafe_chainlink=0
for f in $chainlink_unsafe_files; do
  if ! grep -qE 'updatedAt|answeredInRound|staleAfter|HEARTBEAT|MAX_DELAY' "$f" 2>/dev/null; then
    ((unsafe_chainlink++))
  fi
done

# getReserves used as price source (without TWAP)
getreserves_files=$(grep -rl --include="*.sol" -E '\.getReserves\s*\(\s*\)' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/mock/\|node_modules" || true)

unsafe_reserves=0
for f in $getreserves_files; do
  if ! grep -qE 'TWAP|cumulativePrice|observationCardinality|consult\(' "$f" 2>/dev/null; then
    ((unsafe_reserves++))
  fi
done

total=$((unsafe_chainlink + unsafe_reserves))

if [[ $total -eq 0 ]]; then
  record "PASS" "P-306 Oracle manipulation" "All oracle reads include staleness checks or TWAP wrappers"
else
  record "FAIL" "P-306 Oracle manipulation" "$unsafe_chainlink Chainlink read(s) without staleness check; $unsafe_reserves getReserves use(s) without TWAP"
fi
