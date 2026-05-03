#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-716
name: Unbounded Array Iteration (Gas DoS)
description: Detects storage arrays that grow under caller influence and are iterated in a loop without a MAX_LENGTH cap. An attacker who can cheaply cause `array.push(...)` (e.g., by sending dust deposits to non-funder addresses) can grow the array until any function iterating it exceeds the block gas limit, permanently bricking the contract. The fix is a hard MAX_* constant checked before push, with the rejection path returning funds to the caller cleanly.
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
frameworks: OWASP-SC-Top-10:2025:SC09, CWE:835
cwe: 835
false_positive_rate: medium
performance_class: fast
origin: digital_escrow SwapEscrow heldDepositors (March 2026) — non-funder deposits were tracked in an unbounded array iterated by return_all_held_deposits and _doTerminate. Fix introduced MAX_HELD_DEPOSITORS = 10 with a clean revert + ERC20 refund path on overflow.
PRESTON_META

echo "P-716: Unbounded Array Iteration (Gas DoS)"

SRC="${SOURCE_DIR:-.}"
sol_files=$(grep -rl --include="*.sol" -E 'address\s*\[\s*\]|uint256\s*\[\s*\]|\.push\s*\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-716 Unbounded iteration" "No storage-array contracts detected"
  return 0 2>/dev/null || true
fi

bad=""
for f in $sol_files; do
  has_push=$(grep -cE '\.push\s*\(' "$f" 2>/dev/null)
  has_loop=$(grep -cE 'for\s*\([^;]*;\s*[^;]*\.length\s*;' "$f" 2>/dev/null)
  has_max=$(grep -cE 'MAX_[A-Z_]+\s*=|require\s*\([^)]*\.length\s*<|<\s*MAX_' "$f" 2>/dev/null)
  if [[ ${has_push:-0} -gt 0 && ${has_loop:-0} -gt 0 && ${has_max:-0} -eq 0 ]]; then
    bad="${bad}${f}"$'\n'
  fi
done
bad=$(echo "$bad" | sed '/^$/d')

s=$(echo "$sol_files" | wc -l | tr -d ' ')
b=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-716 Unbounded iteration" "$s array-bearing file(s); MAX_* bound or no push+loop combination"
else
  record "WARN" "P-716 Unbounded iteration" "$b file(s) push to storage arrays AND iterate them, with no MAX_ bound" "$bad"
fi
