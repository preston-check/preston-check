#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-423
name: OWASP Mobile M4 — Insufficient Input/Output Validation
description: Detects mobile input/output handling issues — WebView with JavaScript bridges that execute attacker-controlled input, unvalidated deep-link parameters, SQL injection in mobile DBs.
category: code-scan
severity: high
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "db\.Query|db\.Exec|sqlx\.Get|gorm\.Where" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-423 mobile input validation (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-423 mobile input validation (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "sqlx::query|diesel::sql_query|tokio_postgres|\.query\(" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-423 mobile input validation (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-423 mobile input validation (Rust)" "No issues found in Rust files"
  fi
fi
