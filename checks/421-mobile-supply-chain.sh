#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-421
name: OWASP Mobile M2 — Inadequate Supply Chain Security
description: Detects mobile supply chain risks — third-party SDKs without integrity verification, unpinned mobile dependencies, missing Play Integrity / DeviceCheck attestation.
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
frameworks: OWASP-MAS:2024:M2, NIST-CSF:2.0:GV.SC, ISO-27001:2022:5.19
false_positive_rate: high
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M2 — Inadequate Supply Chain Security.
PRESTON_META

echo "P-421: Mobile Supply Chain Security"

SRC="${SOURCE_DIR:-.}"
attest=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "PlayIntegrityApi|DeviceCheck|attestation|App[_-]Attest|SafetyNet|integrityToken" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$attest" ]] && record "PASS" "P-421 mobile supply chain" "$(echo "$attest" | wc -l | tr -d ' ') attestation reference(s)" \
  || record "WARN" "P-421 mobile supply chain" "No Play Integrity / DeviceCheck / App Attest references found"

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "kms\.New|kms\.Decrypt|secretsmanager" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-421 mobile supply chain (Go)" "$_go_count instance(s) found in Go code"
  else
    record "WARN" "P-421 mobile supply chain (Go)" "No secure secrets management references found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "aws_sdk_kms|rusoto_kms|KmsClient" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-421 mobile supply chain (Rust)" "$_rs_count instance(s) found in Rust code"
  else
    record "WARN" "P-421 mobile supply chain (Rust)" "No secure secrets management references found in Rust files"
  fi
fi
