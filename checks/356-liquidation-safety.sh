#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-356
name: DeFi Liquidation Safety
description: Detects liquidation logic in lending and perpetuals protocols that consults stale oracles, uses spot prices instead of TWAP, lacks partial-liquidation correctness, or omits liquidation incentive bounds. Liquidation bugs cause cascading losses (Aave, Compound, MakerDAO have all had liquidation incidents).
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
frameworks: OWASP-SC-Top-10:2025:SC02
cwe: 682
false_positive_rate: high
performance_class: fast
origin: MakerDAO Black Thursday (March 2020), Mango Markets (October 2022), Aave V2 issues — all involved liquidation paths interacting badly with oracle freshness or partial-fill correctness.
PRESTON_META

echo "P-356: Liquidation Safety"

SRC="${SOURCE_DIR:-.}"

# Find liquidation logic
liq_files=$(grep -rl --include="*.sol" \
  -E 'function\s+(liquidate|liquidatePosition|forceLiquidate|liquidationCall|seizeCollateral)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$liq_files" ]]; then
  record "SKIP" "P-356 Liquidation safety" "No liquidation logic detected"
  return 0 2>/dev/null || true
fi

unsafe=0
total=0
for f in $liq_files; do
  ((total++))
  has_freshness=$(grep -cE 'updatedAt|HEARTBEAT|MAX_DELAY|staleAfter|TWAP|consult\(|cumulativePrice' "$f" 2>/dev/null || echo 0)
  has_bounds=$(grep -cE 'MAX_LIQUIDATION_INCENTIVE|liquidationBonus|maxBonus|partialLiquidation|closeFactor' "$f" 2>/dev/null || echo 0)
  if [[ ${has_freshness:-0} -eq 0 || ${has_bounds:-0} -eq 0 ]]; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-356 Liquidation safety" "$total liquidation contract(s) check oracle freshness and bounds"
else
  record "FAIL" "P-356 Liquidation safety" "$unsafe of $total liquidation contract(s) lack oracle freshness or incentive-bounds checks"
fi
