#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-711
name: On-Chain Preimage Storage (Cross-Chain Front-Running)
description: Detects HTLC contracts that persist the revealed preimage in storage after a claim. The preimage MUST only be emitted in events and never stored on-chain. Once a preimage is publicly readable from contract state on chain A, an attacker can front-run the legitimate counter-claim on chain B by reading htlc.preimage and submitting their own claim there before the original recipient does.
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
frameworks: OWASP-SC-Top-10:2025:SC04, CWE:200
cwe: 200
false_positive_rate: low
performance_class: fast
origin: digital_escrow HTLC SC-C2 (Jan 2026) — the original implementation stored preimage in the HTLC struct for "future verification". The fix removes the assignment entirely and emits the preimage in HTLCClaimed only. getPreimage() was kept as a deprecated stub that always returns bytes32(0).
PRESTON_META

echo "P-711: On-Chain Preimage Storage (Cross-Chain Front-Running)"

SRC="${SOURCE_DIR:-.}"
htlc_files=$(grep -rl --include="*.sol" -E '\b(hashLock|preimage|HTLC)\b' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$htlc_files" ]]; then
  record "SKIP" "P-711 On-chain preimage" "No HTLC contracts detected"
  return 0 2>/dev/null || true
fi

# Look for assignments that persist a preimage to storage:
#   htlc.preimage = preimage;
#   preimages[id] = preimage;
#   storedPreimage = preimage;
# Excludes function parameter declarations and struct field declarations (we only flag writes).
stored=""
for f in $htlc_files; do
  hits=$(grep -nE '^\s*(\w+\.preimage|preimages\s*\[|storedPreimage)\s*=\s*' "$f" 2>/dev/null \
    | grep -vE '^\s*//' || true)
  if [[ -n "$hits" ]]; then
    stored="${stored}${f}: ${hits}"$'\n'
  fi
done
stored=$(echo "$stored" | sed '/^$/d')

h=$(echo "$htlc_files" | wc -l | tr -d ' ')
s=$([[ -n "$stored" ]] && echo "$stored" | wc -l | tr -d ' ' || echo 0)

if [[ ${s:-0} -eq 0 ]]; then
  record "PASS" "P-711 On-chain preimage" "$h HTLC file(s); no on-chain preimage persistence detected"
else
  record "FAIL" "P-711 On-chain preimage" "$s preimage write(s) to storage in HTLC contract(s) — enables cross-chain front-run" "$stored"
fi
