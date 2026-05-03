#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-706
name: ERC-20 Approve Race Condition
description: Detects ERC-20 token contracts whose approve() implementation does not address the well-known race condition: a spender can use both the old and new allowance if the owner changes the value without first setting it to zero. Mitigations are increaseAllowance/decreaseAllowance or atomic safeApprove patterns.
category: code-scan
severity: medium
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04, CWE:362
cwe: 362
false_positive_rate: medium
performance_class: fast
origin: Documented since 2017 in the ERC-20 standard issues; persists because many ERC-20 implementations copy reference code without the increase/decreaseAllowance pattern.
PRESTON_META

echo "P-706: ERC-20 Approve Race"

SRC="${SOURCE_DIR:-.}"
erc20=$(grep -rl --include="*.sol" -E 'function\s+approve\s*\([^)]*spender[^)]*amount[^)]*\)\s+(external|public)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$erc20" ]]; then
  record "SKIP" "P-706 ERC-20 approve race" "No ERC-20 approve() implementations detected"
  return 0 2>/dev/null || true
fi

mitigation=$(grep -rln --include="*.sol" -E 'function\s+(increaseAllowance|decreaseAllowance|safeApprove)\s*\(|forceApprove' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

t=$(echo "$erc20" | wc -l | tr -d ' ')
m=$([[ -n "$mitigation" ]] && echo "$mitigation" | wc -l | tr -d ' ' || echo 0)

if [[ ${m:-0} -gt 0 ]]; then
  record "PASS" "P-706 ERC-20 approve race" "$t ERC-20 contract(s); $m file(s) provide increase/decreaseAllowance"
else
  record "WARN" "P-706 ERC-20 approve race" "$t ERC-20 contract(s) without observable increase/decreaseAllowance mitigation" "$(echo "$erc20" | head -10)"
fi
