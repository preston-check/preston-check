#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-308
name: Bridge Replay Protection
description: Detects cross-chain bridge message handlers that lack nonce, chainId, or sourceChain enforcement. Replay attacks across chains caused some of the largest crypto exploits in history (Wormhole 2022 -$320M, Nomad 2022 -$190M). Every bridge message must include and enforce a unique identifier and the originating chain ID.
category: code-scan
severity: critical
languages: solidity, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02
cwe: 294
false_positive_rate: medium
performance_class: fast
origin: Wormhole bridge ($320M, Feb 2022) and Nomad bridge ($190M, Aug 2022) were both compromised through insufficient cross-chain message validation.
PRESTON_META

echo "P-308: Bridge Replay Protection"

SRC="${SOURCE_DIR:-.}"

# Find files that look like bridge/cross-chain message handlers
bridge_files=$(grep -rl --include="*.sol" --include="*.go" --include="*.rs" \
  -E 'BridgeMessage|CrossChainMessage|relayMessage|executeMessage|handleCrossChainMessage|onMessageReceived|verifyMessage|attestation' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/mock/\|node_modules\|vendor/" || true)

if [[ -z "$bridge_files" ]]; then
  record "SKIP" "P-308 Bridge replay" "No bridge/cross-chain message handlers detected"
  return 0 2>/dev/null || true
fi

unsafe=0
total=0
for f in $bridge_files; do
  ((total++))
  has_nonce=$(grep -cE 'nonce|messageId|messageHash|usedNonces|processedMessages|seenMessages' "$f" 2>/dev/null || echo 0)
  has_chainid=$(grep -cE 'sourceChain|chainId|originChain|srcChainId|chainID' "$f" 2>/dev/null || echo 0)
  if [[ ${has_nonce:-0} -eq 0 || ${has_chainid:-0} -eq 0 ]]; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-308 Bridge replay" "$total bridge handler(s) include nonce + chainId enforcement"
else
  record "FAIL" "P-308 Bridge replay" "$unsafe of $total bridge handler(s) lack nonce or chainId enforcement"
fi
