#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-719
name: Insecure Randomness from Block Data
description: Detects use of block.timestamp, block.difficulty, blockhash, or block.prevrandao as the sole entropy source in non-ID, non-deterministic contexts (e.g., NFT trait minting, lottery picking, prize distribution, key derivation). Validators / proposers can manipulate or predict these values within a block, so any value-bearing decision derived from them is exploitable. Use Chainlink VRF or commit-reveal with a long enough reveal window for any randomness that controls fund distribution.
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
frameworks: OWASP-SC-Top-10:2025:SC07, CWE:330
cwe: 330
false_positive_rate: high
performance_class: fast
origin: digital_escrow MPC C-4 (Nov 2025) — Math.random() was used in shard-derivation off-chain code; the smart-contract analog is block-data randomness. Numerous on-chain incidents (Fomo3D, MeebitDAO, FairWin) trace to predictable block.timestamp randomness.
PRESTON_META

echo "P-719: Insecure Randomness from Block Data"

SRC="${SOURCE_DIR:-.}"
sol_files=$(grep -rl --include="*.sol" -E 'block\.(timestamp|difficulty|prevrandao)|blockhash\s*\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-719 Insecure randomness" "No block-data references detected"
  return 0 2>/dev/null || true
fi

# Look for the suspect pattern: keccak256 mixing block-data, used in arithmetic / mod / index context
# (suggesting random-pick, not ID-generation).
suspect=""
for f in $sol_files; do
  hits=$(grep -nE 'keccak256\s*\([^)]*block\.(timestamp|difficulty|prevrandao)' "$f" 2>/dev/null \
    | grep -vE '^\s*//' || true)
  # Heuristic: if the file ALSO has % (mod) or random / lottery / mint / prize / winner naming, flag it
  if [[ -n "$hits" ]]; then
    is_random_context=$(grep -cE '\brandom|\blottery|\bmint|\bprize|\bwinner|\bdraw|\braffle|%\s*[A-Za-z_]+\.length' "$f" 2>/dev/null)
    if [[ ${is_random_context:-0} -gt 0 ]]; then
      suspect="${suspect}${f}: ${hits}"$'\n'
    fi
  fi
done
suspect=$(echo "$suspect" | sed '/^$/d')

s=$(echo "$sol_files" | wc -l | tr -d ' ')
b=$([[ -n "$suspect" ]] && echo "$suspect" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-719 Insecure randomness" "$s block-data file(s); no value-bearing randomness pattern detected"
else
  record "FAIL" "P-719 Insecure randomness" "$b suspect block-data randomness use(s) in value-bearing context" "$suspect"
fi
