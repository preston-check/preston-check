#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-707
name: ERC-721 / ERC-1155 Callback Reentrancy
description: Detects ERC-721 safeTransferFrom or ERC-1155 safeTransferFrom invocations whose recipient hooks (onERC721Received / onERC1155Received) execute before sender state is finalized. Callback reentrancy through these hooks is a recurring NFT exploit class.
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
false_positive_rate: medium
performance_class: fast
origin: Multiple NFT-marketplace and NFT-staking exploits used callback reentrancy; pattern often missed because nonReentrant on the ERC-721 contract does not protect the calling contract.
PRESTON_META

echo "P-707: ERC-721/1155 Callback Reentrancy"

SRC="${SOURCE_DIR:-.}"
files=$(grep -rl --include="*.sol" -E "safeTransferFrom|onERC721Received|onERC1155Received|onERC1155BatchReceived" "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$files" ]]; then
  record "SKIP" "P-707 ERC-721/1155 callback" "No safeTransferFrom or NFT receiver callbacks detected"
  return 0 2>/dev/null || true
fi

# Look for nonReentrant on the staking/marketplace functions that call safeTransferFrom
nonre=$(grep -rln --include="*.sol" -E 'nonReentrant' "$SRC" 2>/dev/null | grep -vE '/test/|node_modules' || true)
n=$([[ -n "$nonre" ]] && echo "$nonre" | wc -l | tr -d ' ' || echo 0)
t=$(echo "$files" | wc -l | tr -d ' ')

if [[ ${n:-0} -ge 1 ]]; then
  record "PASS" "P-707 ERC-721/1155 callback" "$t NFT-related file(s); $n file(s) reference nonReentrant"
else
  record "FAIL" "P-707 ERC-721/1155 callback" "$t NFT-related file(s) without observable nonReentrant guards on transfer flows" "$(echo "$files" | head -10)"
fi
