#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-426
name: OWASP Mobile M7 — Insufficient Binary Protections
description: Detects missing tamper detection, root/jailbreak detection, anti-debug, and binary obfuscation references on mobile builds. Lack of these protections allows trivial reverse-engineering and credential theft on rooted/jailbroken devices.
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
frameworks: OWASP-MAS:2024:M7, OWASP-MASVS:2.0:RESILIENCE-1
false_positive_rate: high
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M7 — Insufficient Binary Protections.
PRESTON_META

echo "P-426: Mobile Binary Protections"

SRC="${SOURCE_DIR:-.}"
prot=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.gradle" --include="*.pbxproj" \
  -iE "RootBeer|isJailbroken|isRooted|FridaDetect|tamperDetect|antiDebug|proguard|dexguard|obfuscat" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$prot" ]] && record "PASS" "P-426 mobile binary protections" "$(echo "$prot" | wc -l | tr -d ' ') binary-protection reference(s)" \
  || record "WARN" "P-426 mobile binary protections" "No tamper-detect / root-detect / obfuscation references found"
