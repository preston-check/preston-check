#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-471
name: PSD2 Inherence Element (Biometric Authentication)
description: Detects support for the inherence element of PSD2 SCA — biometric authentication (FaceID, TouchID, fingerprint, voice). PSD2 RTS Article 8 defines inherence as one of three valid SCA elements.
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
frameworks: PSD2:2018:Art.97, PSD2-RTS:2018:Art.8, OWASP-MASVS:2.0:AUTH-1
false_positive_rate: medium
performance_class: fast
origin: PSD2 RTS Article 8 — inherence (something the user is) as an SCA element.
PRESTON_META

echo "P-471: PSD2 Inherence Element"

SRC="${SOURCE_DIR:-.}"
inh=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.ts" --include="*.tsx" --include="*.js" \
  -iE "FaceID|TouchID|BiometricPrompt|LocalAuthentication|biometric.*authenticate|fingerprint[_-]auth|voice[_-]auth|webauthn|fido2.*platform" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$inh" ]] && record "PASS" "P-471 PSD2 inherence" "$(echo "$inh" | wc -l | tr -d ' ') biometric / inherence reference(s)" \
  || record "WARN" "P-471 PSD2 inherence" "No biometric authentication (inherence element) detected"

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "webauthn|fido2|passkey|BiometricVerif" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-471 PSD2 inherence (Go)" "$_go_count instance(s) found in Go code"
  else
    record "WARN" "P-471 PSD2 inherence (Go)" "No biometric / WebAuthn / FIDO2 references found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "webauthn|fido2|passkey|biometric" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-471 PSD2 inherence (Rust)" "$_rs_count instance(s) found in Rust code"
  else
    record "WARN" "P-471 PSD2 inherence (Rust)" "No biometric / WebAuthn / FIDO2 references found in Rust files"
  fi
fi
