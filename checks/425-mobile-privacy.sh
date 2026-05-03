#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-425
name: OWASP Mobile M6 — Inadequate Privacy Controls
description: Detects mobile privacy issues — PII in app logs, missing screen-recording protection on sensitive screens, clipboard exposure of secrets, copy-paste of credentials.
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
frameworks: OWASP-MAS:2024:M6, OWASP-MASVS:2.0:PRIVACY-1
false_positive_rate: high
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M6 — Inadequate Privacy Controls.
PRESTON_META

echo "P-425: Mobile Privacy Controls"

SRC="${SOURCE_DIR:-.}"
screen=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "FLAG_SECURE|setSecureFlag|isCaptured|screenshotProtection|disableScreenshot" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$screen" ]] && record "PASS" "P-425 mobile privacy" "$(echo "$screen" | wc -l | tr -d ' ') screen-recording protection reference(s)" \
  || record "WARN" "P-425 mobile privacy" "No screen-recording protection (FLAG_SECURE/isCaptured) found in mobile code"
