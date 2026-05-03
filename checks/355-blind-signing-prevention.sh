#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-355
name: Blind Signing Prevention (What-You-See-Is-What-You-Sign)
description: Verifies that hardware wallet integrations refuse blind signing — signing of opaque hashes without parsing and displaying the underlying transaction data on the device. Blind signing is how phishing dApps trick users into approving malicious transactions through Ledger/Trezor when the device cannot parse the contract call.
category: code-scan
severity: high
languages: typescript, javascript, swift, kotlin
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.AC, OWASP-MASVS:2.0:AUTH-2
cwe: 451
false_positive_rate: medium
performance_class: fast
origin: Ledger and Trezor have published security advisories repeatedly warning that blind-signing is the proximate cause of many smart-wallet drainings; "what you see is what you sign" became the industry catchphrase post-Bybit.
PRESTON_META

echo "P-355: Blind Signing Prevention"

SRC="${SOURCE_DIR:-.}"

hw_signing=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.swift" --include="*.kt" \
  -iE 'ledgerSign|trezorSign|hwSigner.signTransaction|@ledgerhq/hw-app|TrezorConnect\.ethereumSign' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$hw_signing" ]]; then
  record "SKIP" "P-355 Blind signing prevention" "No hardware wallet signing flows detected"
  return 0 2>/dev/null || true
fi

# Look for clear-signing / EIP-712 typed data / ABI parsing on device
clear_signing=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.swift" --include="*.kt" \
  -iE 'clearSigning|clear_signing|wysiwys|displayedFields|parsedOnDevice|abiParsing|EIP-712|signTypedData|ledgerEthereumApp.*provideTokenInfo|provideERC20|provideNFTInfo' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Anti-pattern: explicit blind-sign acceptance
blind_accept=$(grep -rn --include="*.ts" --include="*.js" --include="*.swift" --include="*.kt" \
  -iE 'allowBlindSign\s*[:=]\s*true|blindSigning\s*[:=]\s*true|allowOpaqueSign\s*[:=]\s*true' "$SRC" 2>/dev/null \
  | grep -vE '/test/' || true)

if [[ -n "$blind_accept" ]]; then
  count=$(echo "$blind_accept" | wc -l | tr -d ' ')
  record "FAIL" "P-355 Blind signing prevention" "$count occurrence(s) explicitly enable blind signing on hardware wallets" "$(echo "$blind_accept" | head -10)"
elif [[ -n "$clear_signing" ]]; then
  count=$(echo "$clear_signing" | wc -l | tr -d ' ')
  record "PASS" "P-355 Blind signing prevention" "$count file(s) reference clear-signing or ABI-parsed device display"
else
  record "WARN" "P-355 Blind signing prevention" "Hardware wallet signing without clear-signing / typed-data references" "$(echo "$blind_accept" | head -10)"
fi
