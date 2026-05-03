#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-471
name: PSD2 Inherence Element (Biometric Authentication)
description: Detects support for the inherence element of PSD2 SCA — biometric authentication (FaceID, TouchID, fingerprint, voice). PSD2 RTS Article 8 defines inherence as one of three valid SCA elements.
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
frameworks: PSD2:2018:Art.97, PSD2-RTS:2018:Art.8, OWASP-MASVS:2.0:AUTH-1
false_positive_rate: medium
performance_class: fast
origin: PSD2 RTS Article 8 — inherence (something the user is) as an SCA element.
PRESTON_META

echo "P-471: PSD2 Inherence Element"

SRC="${SOURCE_DIR:-.}"
inh=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.ts" --include="*.tsx" --include="*.js" \
  -iE "FaceID|TouchID|BiometricPrompt|LocalAuthentication|biometric.*authenticate|fingerprint[_-]auth|voice[_-]auth|webauthn|fido2.*platform" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$inh" ]] && record "PASS" "P-471 PSD2 inherence" "$(echo "$inh" | wc -l | tr -d ' ') biometric / inherence reference(s)" \
  || record "WARN" "P-471 PSD2 inherence" "No biometric authentication (inherence element) detected"
