#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-704
name: Front-Running and Mempool Exposure
description: Detects state-changing operations whose ordering matters and which are exposed in the public mempool — auctions, bid-collection, reveal-of-secret patterns. Without commit-reveal or private-mempool routing, MEV bots can front-run user transactions.
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
frameworks: OWASP-SC-Top-10:2025:SC04
cwe: 362
false_positive_rate: high
performance_class: fast
origin: MEV extraction from naive auction/bid implementations is a multi-billion-dollar industry; commit-reveal schemes are the canonical defense.
PRESTON_META

echo "P-704: Front-Running / Mempool Exposure"

SRC="${SOURCE_DIR:-.}"
sensitive_ops=$(grep -rln --include="*.sol" -E 'function\s+(bid|placeOrder|submitBid|claim|reveal|swap|exchange|fillOrder)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$sensitive_ops" ]]; then
  record "SKIP" "P-704 Front-running" "No order-sensitive operations detected"
  return 0 2>/dev/null || true
fi

defenses=$(grep -rln --include="*.sol" -iE "commit[_-]?reveal|commitHash|hashCommitment|flashbots|merkle[_-]?bid|sealed[_-]?bid|private[_-]?mempool|nonReentrant" "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

s_count=$(echo "$sensitive_ops" | wc -l | tr -d ' ')
d_count=$([[ -n "$defenses" ]] && echo "$defenses" | wc -l | tr -d ' ' || echo 0)

if [[ ${d_count:-0} -gt 0 ]]; then
  record "PASS" "P-704 Front-running" "$s_count sensitive operation(s); $d_count defense reference(s) (commit-reveal, sealed-bid, etc.)"
else
  sample=$(echo "$sensitive_ops" | head -10)
  record "WARN" "P-704 Front-running" "$s_count order-sensitive operations without observable commit-reveal or sealed-bid pattern" "$sample"
fi
