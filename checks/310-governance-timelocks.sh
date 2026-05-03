#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-310
name: Governance Time-Locks on Privileged Operations
description: Detects privileged admin functions (upgradeTo, setOwner, setMinter, setFee, mint, pause) that lack time-lock delays. Admin keys without time-locks let a compromised admin or malicious insider drain protocol funds instantly; time-locks give the community a window to detect, alert, and respond.
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
frameworks: OWASP-SC-Top-10:2025:SC01
cwe: 269
false_positive_rate: medium
performance_class: fast
origin: Multiple admin-key compromises (e.g., DeFi protocols where stolen admin keys were used to immediately drain treasuries) demonstrated the value of time-lock delays as defense-in-depth.
PRESTON_META

echo "P-310: Governance Time-Locks"

SRC="${SOURCE_DIR:-.}"
sol_count=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')

if [[ "$sol_count" -eq 0 ]]; then
  record "SKIP" "P-310 Governance time-locks" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

# Find privileged functions
priv_files=$(grep -rl --include="*.sol" \
  -E 'function\s+(upgradeTo|setOwner|transferOwnership|setMinter|setAdmin|setFee|mint|setImplementation|pause|unpause)' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/mock/\|node_modules" || true)

if [[ -z "$priv_files" ]]; then
  record "PASS" "P-310 Governance time-locks" "No obvious privileged admin functions detected"
  return 0 2>/dev/null || true
fi

unprotected=0
total=0
for f in $priv_files; do
  ((total++))
  if ! grep -qE 'TimelockController|Timelock|onlyTimelock|delay\s*>\s*[0-9]+|MIN_DELAY|GOVERNANCE_DELAY|onlyGovernance' "$f" 2>/dev/null; then
    ((unprotected++))
  fi
done

if [[ $unprotected -eq 0 ]]; then
  record "PASS" "P-310 Governance time-locks" "$total contract(s) with privileged functions all reference timelock guards"
else
  record "WARN" "P-310 Governance time-locks" "$unprotected of $total contract(s) with privileged admin functions lack visible timelock guard"
fi
