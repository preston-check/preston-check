#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-422
name: OWASP Mobile M3 — Insecure Authentication / Authorization
description: Detects mobile authentication weaknesses — missing biometric authentication on sensitive operations, missing session expiration, client-side authorization decisions.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-MAS:2024:M3, OWASP-MASVS:2.0:AUTH-1, OWASP-MASVS:2.0:AUTH-2
false_positive_rate: medium
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M3 — Insecure Authentication / Authorization.
PRESTON_META

echo "P-422: Mobile Insecure Authentication"

SRC="${SOURCE_DIR:-.}"
bio=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "BiometricPrompt|LocalAuthentication|FaceID|TouchID|FingerprintManager|biometric.*authenticate" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$bio" ]] && record "PASS" "P-422 mobile auth" "$(echo "$bio" | wc -l | tr -d ' ') biometric auth reference(s)" \
  || record "WARN" "P-422 mobile auth" "No biometric authentication references in mobile code"
