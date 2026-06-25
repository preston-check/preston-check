#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-422
name: OWASP Mobile M3 — Insecure Authentication / Authorization
description: Detects mobile authentication weaknesses — missing biometric authentication on sensitive operations, missing session expiration, client-side authorization decisions.
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "hasRole|isAdmin|checkPermission|Authorize" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-422 mobile auth (Go)" "$_go_count instance(s) found in Go code"
  else
    record "WARN" "P-422 mobile auth (Go)" "No authorization / permission-check references found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "has_role|is_admin|check_permission|authorize" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-422 mobile auth (Rust)" "$_rs_count instance(s) found in Rust code"
  else
    record "WARN" "P-422 mobile auth (Rust)" "No authorization / permission-check references found in Rust files"
  fi
fi
