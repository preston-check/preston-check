#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-351
name: Smart Contract Access Control (OWASP SC1:2025)
description: Detects external/public Solidity functions that mutate state or move value without onlyOwner, AccessControl roles, or equivalent authorization. Access Control is the #1 cause of smart contract losses in 2025 ($953M according to OWASP SC Top 10:2025), surpassing reentrancy by an order of magnitude.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC01, CWE:284
cwe: 284
false_positive_rate: medium
performance_class: fast
origin: OWASP Smart Contract Top 10 (2025) ranks Access Control as the #1 vulnerability category by financial impact ($953M), leading by a significant margin over all other classes.
PRESTON_META

echo "P-351: Access Control (OWASP SC1:2025)"

SRC="${SOURCE_DIR:-.}"
sol_count=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$sol_count" -eq 0 ]]; then
  record "SKIP" "P-351 Access control" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

# Find privileged-looking functions (mint, burn, transfer, withdraw, set, upgrade, pause)
priv_files=$(grep -rl --include="*.sol" \
  -E 'function\s+(mint|burn|withdraw|setFee|setOwner|setMinter|setAdmin|transferOwnership|upgradeTo|setImplementation|drain|migrate|sweepTokens|rescueTokens|setTreasury|setRouter|setOracle)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock/|node_modules' || true)

if [[ -z "$priv_files" ]]; then
  record "PASS" "P-351 Access control" "No privileged-looking functions detected"
  return 0 2>/dev/null || true
fi

unprotected=0
total=0
for f in $priv_files; do
  ((total++))
  if ! grep -qE 'onlyOwner|onlyAdmin|onlyRole|hasRole|AccessControl|Ownable|require[^)]*msg\.sender\s*==\s*owner|_checkRole|onlyGovernance|onlyMinter|require[^)]*authorized|onlyAuthorized' "$f" 2>/dev/null; then
    ((unprotected++))
  fi
done

if [[ $unprotected -eq 0 ]]; then
  record "PASS" "P-351 Access control" "$total contract(s) with privileged functions all reference access modifiers"
else
  record "FAIL" "P-351 Access control" "$unprotected of $total contract(s) have privileged functions without visible access control" "$(echo "$priv_files" | head -10)"
fi
