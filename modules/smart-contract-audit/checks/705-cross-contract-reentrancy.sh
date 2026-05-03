#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-705
name: Cross-Contract Reentrancy
description: Detects reentrancy patterns that exploit shared state across contract boundaries. Single-contract reentrancy is well-known; cross-contract reentrancy (where Contract A's nonReentrant guard does not protect Contract B's shared state) is a more subtle and recurring class.
category: code-scan
severity: high
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC05
cwe: 841
false_positive_rate: high
performance_class: fast
origin: Cream Finance (October 2021, $130M), Sushi MISO (September 2021), Read-only reentrancy class — recurring pattern not caught by single-contract nonReentrant guards.
PRESTON_META

echo "P-705: Cross-Contract Reentrancy"

SRC="${SOURCE_DIR:-.}"
shared_state=$(grep -rln --include="*.sol" -E 'function\s+\w+\s*\([^)]*\)\s+(external|public).*returns?.*\(' "$SRC" 2>/dev/null \
  | xargs grep -l -E 'mapping\s*\(\s*address|mapping\s*\(\s*uint' 2>/dev/null | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$shared_state" ]]; then
  record "SKIP" "P-705 Cross-contract reentrancy" "No shared-state external functions detected"
  return 0 2>/dev/null || true
fi

view_calls=$(grep -rn --include="*.sol" -E 'function\s+\w+\s*\([^)]*\)\s+(external|public)\s+view\s+returns' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' | head -30 || true)

read_only_guards=$(grep -rln --include="*.sol" -iE "readOnlyReentrancyGuard|nonReentrantView|crossContractGuard" "$SRC" 2>/dev/null || true)

if [[ -n "$read_only_guards" ]]; then
  record "PASS" "P-705 Cross-contract reentrancy" "Read-only/cross-contract reentrancy guards in place"
else
  vc=$([[ -n "$view_calls" ]] && echo "$view_calls" | wc -l | tr -d ' ' || echo 0)
  record "WARN" "P-705 Cross-contract reentrancy" "Shared-state contracts with $vc view function(s); verify read-only reentrancy not exploitable" "$(echo "$shared_state" | head -10)"
fi
