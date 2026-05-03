#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-715
name: Critical Immutable Address Without Rotation Path
description: Detects contracts that declare critical addresses (handler, owner, signer, oracle, treasury) as `immutable` without a corresponding rotation / proposal function. If the immutable key is compromised post-deploy, the only remedy is full contract redeployment + state migration — usually impossible for fund-holding contracts. Any custodial role that controls value movement needs a rotation path with multi-sig + extended timelock (48h+ recommended).
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
frameworks: OWASP-SC-Top-10:2025:SC10, CWE:284
cwe: 284
false_positive_rate: medium
performance_class: fast
origin: digital_escrow SwapEscrow SC-C3 (March 2026) — handlers were declared immutable. Fix added proposeHandlerRotation / approveHandlerRotation / executeHandlerRotation with 48-hour timelock and ALL-handler approval (stricter than normal multi-sig), plus emitted events for off-chain monitoring.
PRESTON_META

echo "P-715: Critical Immutable Address Without Rotation Path"

SRC="${SOURCE_DIR:-.}"
candidates=$(grep -rln --include="*.sol" -E 'address\s+(public\s+)?immutable\s+(handler|owner|signer|oracle|treasury|admin|guardian|pauser|operator|relayer)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$candidates" ]]; then
  record "SKIP" "P-715 Immutable rotation" "No critical immutable addresses detected"
  return 0 2>/dev/null || true
fi

bad=""
for f in $candidates; do
  has_rotation=$(grep -cE 'proposeHandlerRotation|proposeRotation|setHandler|rotateOwner|transferOwnership|setOracle|setSigner|setTreasury|setOperator' "$f" 2>/dev/null)
  if [[ ${has_rotation:-0} -eq 0 ]]; then
    bad="${bad}${f}"$'\n'
  fi
done
bad=$(echo "$bad" | sed '/^$/d')

c=$(echo "$candidates" | wc -l | tr -d ' ')
b=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-715 Immutable rotation" "$c immutable-role file(s); rotation path present"
else
  record "WARN" "P-715 Immutable rotation" "$b of $c file(s) declare critical immutable addresses without rotation function" "$bad"
fi
