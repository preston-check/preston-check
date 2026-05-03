#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-330
name: High-Value Transaction Step-Up Authentication
description: Verifies that high-value crypto transfers require additional authentication beyond a session token (hardware key, FIDO2/WebAuthn, video KYC, manual approval). Session tokens are routinely stolen via phishing, malware, or session-fixation; step-up auth on high-value movements blocks the cash-out path.
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
frameworks: NIST-CSF:2.0:PR.AC, PSD2:2018:Art.97, ISO-27001:2022:A.5.17
cwe: 308
false_positive_rate: low
performance_class: fast
origin: PSD2 SCA mandate plus exchange-best-practice (Coinbase Vault, Binance Withdraw Whitelist, Kraken Master Key) demonstrate this as the default control for high-value flows.
PRESTON_META

echo "P-330: Step-Up Auth on High-Value Sends"

SRC="${SOURCE_DIR:-.}"

withdraw_files=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'withdraw[A-Z]|sendCrypto|broadcastTransaction|cryptoTransfer' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$withdraw_files" ]]; then
  record "SKIP" "P-330 Step-up auth" "No withdrawal/send code detected"
  return 0 2>/dev/null || true
fi

stepup=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'stepUp|step[_-]up[_-]auth|webauthn|fido2|hardware[_-]key|2fa[_-]withdrawal|withdraw[_-]2fa|email[_-]confirm[_-]withdraw|videoKYC|video[_-]verification|manual[_-]approval[_-]queue|highValue[_-]threshold|requiresApproval' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$stepup" ]]; then
  count=$(echo "$stepup" | wc -l | tr -d ' ')
  record "PASS" "P-330 Step-up auth" "$count file(s) reference step-up authentication on high-value flows"
else
  record "FAIL" "P-330 Step-up auth" "Withdrawal flows detected without step-up authentication mechanism" "$(echo "$stepup" | head -10)"
fi
