#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-307
name: Unbounded Token Approvals
description: Detects code that grants unbounded ERC-20 approvals (type(uint256).max, MAX_UINT256, ethers.constants.MaxUint256) without a corresponding revocation path. Unbounded approvals to compromised or malicious contracts have been the proximate cause of many wallet drainings, and best practice is to use exact-amount approvals or to have automated revocation.
category: code-scan
severity: medium
languages: solidity, typescript, javascript
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04
cwe: 1284
false_positive_rate: medium
performance_class: fast
origin: Approval-drainer kits and the Inferno Drainer family extracted hundreds of millions by exploiting forgotten infinite approvals on compromised dApp contracts.
PRESTON_META

echo "P-307: Unbounded Token Approvals"

SRC="${SOURCE_DIR:-.}"

# Detect infinite-approval patterns
hits=$(grep -rn --include="*.sol" --include="*.ts" --include="*.tsx" --include="*.js" \
  -E 'approve\s*\([^)]*type\s*\(\s*uint256\s*\)\.max|approve\s*\([^)]*MAX_UINT256|approve\s*\([^)]*MaxUint256|approve\s*\([^)]*0x[fF]{64}|approve\s*\([^)]*ethers\.constants\.MaxUint256|approve\s*\([^)]*2\s*\*\*\s*256\s*-\s*1' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/spec/\|node_modules\|/mock" || true)

if [[ -z "$hits" ]]; then
  record "PASS" "P-307 Token approvals" "No infinite-approval patterns found"
  return 0 2>/dev/null || true
fi

# Count occurrences and check whether revocation logic exists
count=$(echo "$hits" | wc -l | tr -d ' ')
revoke_pattern=$(grep -rn --include="*.sol" --include="*.ts" --include="*.tsx" --include="*.js" \
  -E 'approve\s*\([^,)]+,\s*0\s*\)|forceApprove\s*\(|safeDecreaseAllowance' "$SRC" 2>/dev/null \
  | grep -v "/test/\|node_modules" | wc -l | tr -d ' ')

if [[ $revoke_pattern -gt 0 ]]; then
  record "WARN" "P-307 Token approvals" "$count infinite-approval call(s) found; revocation pattern present in $revoke_pattern place(s)" "$(echo "$revoke_pattern" | head -10)"
else
  record "FAIL" "P-307 Token approvals" "$count infinite-approval call(s) without any revocation path detected" "$(echo "$revoke_pattern" | head -10)"
fi
