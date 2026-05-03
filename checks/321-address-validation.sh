#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-321
name: Crypto Address Format and Checksum Validation
description: Verifies that crypto addresses are validated for checksum and format before being used as a destination. Untyped or unvalidated address strings can include typos that send funds to unrecoverable burn addresses, or wrong-network addresses that lose funds permanently when sent on the wrong chain.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, OWASP-API:2023:API3
cwe: 20
false_positive_rate: medium
performance_class: fast
origin: User-typed crypto addresses are routinely truncated, transposed, or copy-pasted with hidden characters; unrecoverable losses are common when validation is absent.
PRESTON_META

echo "P-321: Crypto Address Validation"

SRC="${SOURCE_DIR:-.}"

# Look for address-handling code
addr_files=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'recipient[_-]address|toAddress|destinationAddress|withdrawAddress|payoutAddress|to:.*0x' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$addr_files" ]]; then
  record "SKIP" "P-321 Address validation" "No address-handling code paths detected"
  return 0 2>/dev/null || true
fi

# Check that validation is performed
unvalidated=0
total=0
for f in $addr_files; do
  ((total++))
  # Look for any validation library use
  if ! grep -qE 'isAddress|toChecksumAddress|getAddress|validate[_-]?address|address[_-]validator|web3\.utils\.isAddress|ethers\.utils\.isAddress|ethers\.isAddress|bitcoinjs|bitcore|cardano-serialization-lib|@solana/web3\.js.*PublicKey|XRPL.*isValidAddress|StrKey\.isValidEd25519PublicKey' "$f" 2>/dev/null; then
    ((unvalidated++))
  fi
done

if [[ $unvalidated -eq 0 ]]; then
  record "PASS" "P-321 Address validation" "$total file(s) handle addresses with validation library calls"
else
  record "WARN" "P-321 Address validation" "$unvalidated of $total file(s) handle addresses without visible checksum/format validation"
fi
