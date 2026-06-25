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
# KMS/secretsmanager are key-management patterns, not supply chain controls.
# Supply chain for Go = go.sum present (dependency pinning) + vuln scanning in CI.
_go_sum=$(find "$SRC" -name "go.sum" -not -path "*/vendor/*" 2>/dev/null | head -1)
_go_vuln=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.sh" \
  -E "govulncheck|nancy|snyk|trivy|grype|cosign|sigstore|cyclonedx|syft" \
  "$SRC" 2>/dev/null | grep -vE "node_modules" || true)
if [[ -n "$_go_sum" && -n "$_go_vuln" ]]; then
  record "PASS" "P-421 supply chain (Go)" "go.sum present and dependency vulnerability scanning configured"
elif [[ -n "$_go_sum" ]]; then
  record "WARN" "P-421 supply chain (Go)" "go.sum present but no vulnerability scanner (govulncheck, Snyk, Trivy) found in CI"
else
  _go_mod=$(find "$SRC" -name "go.mod" -not -path "*/vendor/*" 2>/dev/null | head -1)
  if [[ -n "$_go_mod" ]]; then
    record "WARN" "P-421 supply chain (Go)" "go.mod found but no go.sum — dependencies are not pinned"
  fi
fi

# --- Rust ---
# Supply chain for Rust = Cargo.lock present + cargo-audit / cargo-deny in CI.
_rs_lock=$(find "$SRC" -name "Cargo.lock" -not -path "*/target/*" 2>/dev/null | head -1)
_rs_audit=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.toml" \
  -E "cargo.audit|cargo.deny|cargo-audit|cargo-deny|cosign|sigstore|cyclonedx|syft" \
  "$SRC" 2>/dev/null | grep -vE "node_modules" || true)
if [[ -n "$_rs_lock" && -n "$_rs_audit" ]]; then
  record "PASS" "P-421 supply chain (Rust)" "Cargo.lock present and dependency audit tooling configured"
elif [[ -n "$_rs_lock" ]]; then
  record "WARN" "P-421 supply chain (Rust)" "Cargo.lock present but no audit tool (cargo-audit, cargo-deny) found in CI"
else
  _rs_toml=$(find "$SRC" -name "Cargo.toml" -not -path "*/target/*" 2>/dev/null | head -1)
  if [[ -n "$_rs_toml" ]]; then
    record "WARN" "P-421 supply chain (Rust)" "Cargo.toml found but no Cargo.lock — dependencies are not pinned"
  fi
fi
