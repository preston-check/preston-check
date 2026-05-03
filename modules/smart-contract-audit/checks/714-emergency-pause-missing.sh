#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-714
name: Emergency Pause Missing on Fund-Holding Contract
description: Detects contracts that move user funds (transfer, transferFrom, safeTransfer, withdraw) but have no Pausable / whenNotPaused integration and no emergencyPause function. When a vulnerability is discovered post-deploy, the only mitigation without a pause switch is full migration — losing days while funds are at risk. Every contract that custodies user funds should have a pause path, and at least one role should be able to trigger it within seconds (no multi-sig delay for emergency-stop only).
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
frameworks: OWASP-SC-Top-10:2025:SC09, CWE:404
cwe: 404
false_positive_rate: medium
performance_class: fast
origin: digital_escrow SwapEscrow SC-H2 (March 2026) — escrow holding live swap funds had no pause path. Fix added emergencyPause() callable by any handler immediately, with multi-sig required for unpause. The asymmetry is intentional: pause must be fast, unpause must be deliberate.
PRESTON_META

echo "P-714: Emergency Pause Missing on Fund-Holding Contract"

SRC="${SOURCE_DIR:-.}"
fund_files=$(grep -rl --include="*.sol" -E '\b(safeTransfer|transferFrom|safeTransferFrom|\.call\{value)\b' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$fund_files" ]]; then
  record "SKIP" "P-714 Emergency pause" "No fund-moving contracts detected"
  return 0 2>/dev/null || true
fi

unpaused=""
for f in $fund_files; do
  has_pause=$(grep -cE 'Pausable|whenNotPaused|emergencyPause|_pause\s*\(' "$f" 2>/dev/null)
  if [[ ${has_pause:-0} -eq 0 ]]; then
    unpaused="${unpaused}${f}"$'\n'
  fi
done
unpaused=$(echo "$unpaused" | sed '/^$/d')

f_count=$(echo "$fund_files" | wc -l | tr -d ' ')
u_count=$([[ -n "$unpaused" ]] && echo "$unpaused" | wc -l | tr -d ' ' || echo 0)

if [[ ${u_count:-0} -eq 0 ]]; then
  record "PASS" "P-714 Emergency pause" "$f_count fund-moving file(s); pause path present in all"
elif [[ ${u_count:-0} -lt $((f_count / 2 + 1)) ]]; then
  record "WARN" "P-714 Emergency pause" "$u_count of $f_count fund-moving file(s) lack Pausable / whenNotPaused" "$unpaused"
else
  record "FAIL" "P-714 Emergency pause" "$u_count of $f_count fund-moving file(s) lack any emergency-pause path" "$unpaused"
fi
