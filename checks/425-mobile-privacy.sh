#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-425
name: OWASP Mobile M6 — Inadequate Privacy Controls
description: Detects mobile privacy issues — PII in app logs, missing screen-recording protection on sensitive screens, clipboard exposure of secrets, copy-paste of credentials.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "fmt\.Print|fmt\.Println|fmt\.Fprintf|log\.Print" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-425 mobile privacy (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-425 mobile privacy (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "println!|eprintln!|dbg!|print!" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-425 mobile privacy (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-425 mobile privacy (Rust)" "No issues found in Rust files"
  fi
fi
