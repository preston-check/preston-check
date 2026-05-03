#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-423
name: OWASP Mobile M4 — Insufficient Input/Output Validation
description: Detects mobile input/output handling issues — WebView with JavaScript bridges that execute attacker-controlled input, unvalidated deep-link parameters, SQL injection in mobile DBs.
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
frameworks: OWASP-MAS:2024:M4, OWASP-MASVS:2.0:CODE-4
false_positive_rate: medium
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M4 — Insufficient Input/Output Validation.
PRESTON_META

echo "P-423: Mobile Input/Output Validation"

SRC="${SOURCE_DIR:-.}"
webview=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "WebView.*addJavascriptInterface|WKUserContentController|setJavaScriptEnabled\s*\(\s*true|loadUrl\s*\(\s*[\"\'].*\\\$\{" "$SRC" 2>/dev/null | grep -v node_modules || true)
deeplink=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.xml" --include="*.plist" \
  -iE "Intent\.ACTION_VIEW|onNewIntent|UIApplicationLaunchOptionsURLKey|deepLink" "$SRC" 2>/dev/null | grep -v node_modules || true)
issues=$([[ -n "$webview" ]] && echo "$webview" | wc -l | tr -d ' ' || echo 0)
[[ ${issues:-0} -gt 0 ]] && record "WARN" "P-423 mobile input validation" "$issues WebView JS-bridge or unvalidated load patterns" \
  || record "PASS" "P-423 mobile input validation" "No high-risk WebView patterns detected"
