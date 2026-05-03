#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-341
name: Hardware Wallet Integration
description: Verifies that wallet applications offer or require hardware wallet (Ledger, Trezor, GridPlus, Keystone, Coldcard) integration for high-value users rather than software-only signing. Hardware wallets keep private keys in tamper-resistant secure elements and require physical confirmation for signing.
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
frameworks: NIST-CSF:2.0:PR.DS
cwe: 320
false_positive_rate: high
performance_class: fast
origin: Hardware wallets remain the gold standard for end-user self-custody; absence of HW support is a major friction point for high-net-worth crypto users.
PRESTON_META

echo "P-341: Hardware Wallet Integration"

SRC="${SOURCE_DIR:-.}"

hw_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE '@ledgerhq|ledger[_-]hw|trezor[_-]connect|@trezor|gridplus|keystone[_-]wallet|coldcard|hwSigner|hardwareWallet|hardware[_-]wallet|@ledgerhq/hw-app|webusb.*ledger|webhid.*ledger|usb.*hid.*hw' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find any wallet/signing UI
wallet_ui=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'walletConnect|WalletProvider|connectWallet|signTransaction' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$wallet_ui" ]]; then
  record "SKIP" "P-341 Hardware wallet" "No wallet/signing UI code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$hw_refs" ]]; then
  count=$(echo "$hw_refs" | wc -l | tr -d ' ')
  record "PASS" "P-341 Hardware wallet" "$count file(s) reference hardware wallet integration"
else
  record "WARN" "P-341 Hardware wallet" "Wallet UI without hardware wallet integration (Ledger/Trezor/Coldcard)" "$(echo "$wallet_ui" | head -10)"
fi
