#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-426
name: OWASP Mobile M7 — Insufficient Binary Protections
description: Detects missing tamper detection, root/jailbreak detection, anti-debug, and binary obfuscation references on mobile builds. Lack of these protections allows trivial reverse-engineering and credential theft on rooted/jailbroken devices.
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "subtle\.ConstantTimeCompare|hmac\.Equal" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-426 mobile binary protections (Go)" "$_go_count instance(s) found in Go code"
  else
    record "WARN" "P-426 mobile binary protections (Go)" "No constant-time / cryptographic hardening references found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "ct_eq|ConstantTimeEq|ring::constant_time|subtle::" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-426 mobile binary protections (Rust)" "$_rs_count instance(s) found in Rust code"
  else
    record "WARN" "P-426 mobile binary protections (Rust)" "No constant-time / cryptographic hardening references found in Rust files"
  fi
fi
