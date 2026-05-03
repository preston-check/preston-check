#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-347
name: Fee-on-Transfer / Rebasing Token Handling
description: Verifies that token-handling code accounts for fee-on-transfer tokens (where transfer takes a percentage cut) and rebasing tokens (where balances change between transactions). Naive amount-in == amount-out accounting breaks on these tokens, causing accounting drift, failed swaps, or stuck funds.
category: code-scan
severity: medium
languages: solidity, typescript, javascript, java, python, go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04
cwe: 682
false_positive_rate: medium
performance_class: fast
origin: SafeMoon, RFI-style reflection tokens, and legitimate fee-on-transfer mechanisms (PAXG, STA) all break naive transfer accounting; many DeFi protocols have explicit blocklists for them.
PRESTON_META

echo "P-347: Fee-on-Transfer / Rebasing Tokens"

SRC="${SOURCE_DIR:-.}"

handling=$(grep -rln --include="*.sol" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" \
  -iE 'feeOnTransfer|fee[_-]on[_-]transfer|rebasing|rebase[_-]token|deflationary[_-]token|reflection[_-]token|balanceOf.*before.*after|safemoon|pre[_-]transfer[_-]balance|post[_-]transfer[_-]balance|amountReceived' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find general transfer logic
transfers=$(grep -rln --include="*.sol" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" \
  -iE 'transferFrom|safeTransfer|safeTransferFrom' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$transfers" ]]; then
  record "SKIP" "P-347 Fee-on-transfer" "No token transfer code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$handling" ]]; then
  count=$(echo "$handling" | wc -l | tr -d ' ')
  record "PASS" "P-347 Fee-on-transfer" "$count file(s) handle fee-on-transfer / rebasing token semantics"
else
  record "WARN" "P-347 Fee-on-transfer" "Token transfers without explicit fee-on-transfer / rebasing accounting" "$(echo "$transfers" | head -10)"
fi
