#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-302
name: Integer Overflow Protection (pre-0.8 Solidity)
description: Detects Solidity contracts on pragma versions older than 0.8.0 that perform arithmetic without OpenZeppelin SafeMath. Pre-0.8 Solidity does not check for integer overflow/underflow by default, and unsafe arithmetic on financial values can be exploited to drain balances or mint unbounded tokens.
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
frameworks: OWASP-SC-Top-10:2025:SC03, CWE:682
cwe: 682, 190
false_positive_rate: low
performance_class: fast
origin: Multiple early ERC-20 token exploits (BEC, SMT) used integer overflow to mint trillions of fake tokens before Solidity 0.8.0 made overflow checks default.
PRESTON_META

echo "P-302: Integer Overflow Protection (Solidity)"

SRC="${SOURCE_DIR:-.}"
sol_files=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/test/*" 2>/dev/null)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-302 Integer overflow" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

vulnerable=0
for f in $sol_files; do
  pragma=$(grep -oE 'pragma solidity[^;]+' "$f" 2>/dev/null | head -1)
  # Pre-0.8: pragmas like ^0.4, ^0.5, ^0.6, ^0.7, 0.4.x, 0.5.x, 0.6.x, 0.7.x
  if echo "$pragma" | grep -qE '\^?0\.[4-7]\.|<0\.8|<=0\.7'; then
    if ! grep -qE 'using SafeMath|SafeMath\.|@openzeppelin/contracts/utils/math/SafeMath' "$f" 2>/dev/null; then
      ((vulnerable++))
    fi
  fi
done

if [[ $vulnerable -eq 0 ]]; then
  record "PASS" "P-302 Integer overflow" "All pre-0.8 contracts use SafeMath, or only modern (>=0.8) Solidity present"
else
  record "FAIL" "P-302 Integer overflow" "$vulnerable pre-0.8 Solidity contract(s) without SafeMath" "$(echo "$pragma" | head -10)"
fi
