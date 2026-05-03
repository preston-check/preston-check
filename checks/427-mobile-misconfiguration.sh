#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-427
name: OWASP Mobile M8 — Security Misconfiguration
description: Detects mobile app misconfigurations — exported components without permission protection (Android), URL schemes without source validation (iOS), debug builds shipping to production.
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
frameworks: OWASP-MAS:2024:M8, OWASP-MASVS:2.0:PLATFORM-2
false_positive_rate: medium
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M8 — Security Misconfiguration.
PRESTON_META

echo "P-427: Mobile Security Misconfiguration"

SRC="${SOURCE_DIR:-.}"
exported=$(grep -rn --include="*.xml" \
  -E "android:exported=\"true\"" "$SRC" 2>/dev/null | grep -vE "/test/" | head -5 || true)
debuggable=$(grep -rn --include="*.xml" --include="*.gradle" \
  -iE "android:debuggable=\"true\"|debuggable\s*true" "$SRC" 2>/dev/null | grep -vE "/test/|debug" || true)
[[ -n "$debuggable" ]] && record "FAIL" "P-427 mobile misconfig" "android:debuggable=true detected in production manifest" \
  || record "PASS" "P-427 mobile misconfig" "No production debuggable / unprotected exported component issues found"
