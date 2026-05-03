#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-703
name: Delegatecall to Untrusted Address
description: Detects delegatecall() invocations whose target address is user-controllable or otherwise untrusted. Delegatecall executes arbitrary code in the caller's storage context — if the target is attacker-controlled, the attacker reads and writes the caller's storage, including upgrading proxies and stealing funds.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02, CWE:284
cwe: 284
false_positive_rate: high
performance_class: fast
origin: Delegatecall abuse appears in major exploits (Parity multi-sig, dYdX 2021); pattern is well-known but persists in new code via copy-paste.
PRESTON_META

echo "P-703: Delegatecall Abuse"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rn --include="*.sol" -E '\.delegatecall\s*\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$hits" ]]; then
  record "SKIP" "P-703 Delegatecall abuse" "No delegatecall usage detected"
  return 0 2>/dev/null || true
fi

# Heuristic: delegatecall preceded by user-controllable address (function param, storage variable not initialized at deploy)
unsafe=$(echo "$hits" | grep -E '\.delegatecall\s*\(\s*(_target|target|address\(\s*[a-z]|userAddress|implementation\s*\))' || true)
total=$(echo "$hits" | wc -l | tr -d ' ')
unsafe_count=$([[ -n "$unsafe" ]] && echo "$unsafe" | wc -l | tr -d ' ' || echo 0)

if [[ ${unsafe_count:-0} -gt 0 ]]; then
  sample=$(echo "$unsafe" | head -10)
  record "FAIL" "P-703 Delegatecall abuse" "$unsafe_count delegatecall(s) on potentially user-controlled addresses" "$sample"
else
  record "WARN" "P-703 Delegatecall abuse" "$total delegatecall(s) detected; verify each target is constant or trusted" "$(echo "$hits" | head -10)"
fi
