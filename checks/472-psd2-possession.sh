#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-472
name: PSD2 Possession Element (Device Binding / Hardware Token)
description: Detects support for the possession element of PSD2 SCA — bound device, hardware token (FIDO2), push approval on a registered device. PSD2 RTS Article 7 governs possession requirements.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PSD2:2018:Art.97, PSD2-RTS:2018:Art.7
false_positive_rate: medium
performance_class: fast
origin: PSD2 RTS Article 7 — possession (something the user has) as an SCA element.
PRESTON_META

echo "P-472: PSD2 Possession Element"

SRC="${SOURCE_DIR:-.}"
pos=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "deviceBinding|device[_-]binding|registerDevice|trustedDevice|push[_-]auth|webauthn|fido2|hardware[_-]token|yubikey" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$pos" ]] && record "PASS" "P-472 PSD2 possession" "$(echo "$pos" | wc -l | tr -d ' ') possession reference(s)" \
  || record "WARN" "P-472 PSD2 possession" "No device binding / hardware token / WebAuthn (possession element) detected"
