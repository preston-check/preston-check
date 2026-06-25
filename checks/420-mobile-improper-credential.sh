#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-420
name: OWASP Mobile M1 — Improper Credential Usage
description: Detects mobile-specific credential mishandling — hardcoded credentials in mobile sources, credentials in SharedPreferences without encryption, credentials in NSUserDefaults / iOS plist, credentials in app bundle resources.
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
frameworks: OWASP-MAS:2024:M1, OWASP-MASVS:2.0:STORAGE-1, NIST-CSF:2.0:PR.DS
false_positive_rate: medium
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M1 — Improper Credential Usage; routinely found in app pen-tests.
PRESTON_META

echo "P-420: Mobile Improper Credential Usage"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.tsx" --include="*.plist" \
  -iE "SharedPreferences[^.]*putString[^)]*password|NSUserDefaults.*setObject.*password|api_?key\s*=\s*\"[A-Za-z0-9]{16,}|credential.*hardcoded|encryptedSharedPreferences|EncryptedFile" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)
secure=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "Keychain|Keystore|AndroidKeystore|EncryptedSharedPreferences|SecureStorage|biometric_storage" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)
hits_count=$([[ -n "$hits" ]] && echo "$hits" | wc -l | tr -d ' ' || echo 0)
sec_count=$([[ -n "$secure" ]] && echo "$secure" | wc -l | tr -d ' ' || echo 0)
if [[ ${hits_count:-0} -eq 0 && ${sec_count:-0} -gt 0 ]]; then
  record "PASS" "P-420 mobile credentials" "$sec_count secure-storage reference(s)"
elif [[ ${hits_count:-0} -gt 0 ]]; then
  record "FAIL" "P-420 mobile credentials" "$hits_count credential mishandling pattern(s) detected" "$(echo "$secure" | head -10)"
else
  record "SKIP" "P-420 mobile credentials" "No mobile source code detected"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "password\s*:?=\s*\"|secret\s*:?=\s*\"|apiKey\s*:?=\s*\"" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-420 mobile credential usage (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-420 mobile credential usage (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "password\s*=\s*\"|secret\s*=\s*\"|api_key\s*=\s*\"" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-420 mobile credential usage (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-420 mobile credential usage (Rust)" "No issues found in Rust files"
  fi
fi
