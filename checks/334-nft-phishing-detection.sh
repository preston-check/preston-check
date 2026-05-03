#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-334
name: NFT Phishing and Spam Detection
description: Verifies that incoming NFTs are screened against known phishing collections, spam mints, and malicious tokenURI metadata that links to phishing sites. Receiving a malicious NFT and viewing it in a wallet UI has been used to deliver targeted phishing prompts.
category: code-scan
severity: medium
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:DE.CM
cwe: 451
false_positive_rate: high
performance_class: fast
origin: Spam-mint and phishing-NFT campaigns regularly target Ethereum, Solana, and Polygon wallets; Trezor and Ledger have published advisories on the pattern.
PRESTON_META

echo "P-334: NFT Phishing Detection"

SRC="${SOURCE_DIR:-.}"

nft_handling=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'NFT|ERC721|ERC1155|tokenURI|tokenMetadata|onERC721Received|onERC1155Received' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$nft_handling" ]]; then
  record "SKIP" "P-334 NFT phishing" "No NFT handling code detected"
  return 0 2>/dev/null || true
fi

screen_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'spam[_-]nft|phishing[_-]collection|malicious[_-]uri|tokenURI[_-]validation|reservoir.*spam|nftScamCheck|opensea.*flagged|blocklisted[_-]collection' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$screen_refs" ]]; then
  count=$(echo "$screen_refs" | wc -l | tr -d ' ')
  record "PASS" "P-334 NFT phishing" "$count file(s) reference NFT phishing/spam screening"
else
  record "WARN" "P-334 NFT phishing" "NFT handling without spam/phishing screening (consider Reservoir, OpenSea flags, blocklists)"
fi
