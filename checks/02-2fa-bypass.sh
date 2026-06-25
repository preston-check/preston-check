#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-02
name: 2FA Bypass
description: Detects code paths that skip or disable two-factor authentication.
category: code-scan
severity: critical
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.4.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.5, OWASP-API:2023:API2, NIST-CSF:2.0:PR.AA-3, CIS-v8:6.3
PRESTON_META


# P-02: 2FA bypass paths
# Preston created accounts with 2FA=NONE. This check verifies that no code path
# allows 2FA to be set to NONE without explicit admin override.

echo "P-02: 2FA Bypass Paths"

SRC="${SOURCE_DIR:-.}"

# Check for auth_skip or 2FA NONE hardcoding
bypass=$(grep -rn --include="*.java" \
  "auth_skip\|required_2fa_2proceed.*NONE\|2fa.*NONE\|skip.*2fa\|bypass.*2fa" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|mock\|Mock\|target\|node_modules\|// \|/\*\|WARN\|log\.\|memory" \
  | head -10)

if [[ -z "$bypass" ]]; then
  record "PASS" "P-02 2FA bypass paths" "No 2FA bypass patterns found"
else
  count=$(echo "$bypass" | wc -l | tr -d ' ')
  record "WARN" "P-02 2FA bypass paths" "$count potential 2FA bypass paths (review manually)" "$bypass"
fi

# Check if new accounts can be created with 2FA=NONE
none_default=$(grep -rn --include="*.java" \
  "default_2fa_state.*auth_skip\|NONE.*2fa_state\|set2faState.*NONE" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -z "$none_default" ]]; then
  record "PASS" "P-02 2FA default state" "No default-to-NONE 2FA patterns"
else
  record "FAIL" "P-02 2FA default state" "Found code that defaults 2FA to NONE/skip" "$none_default"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "auth_skip|required_2fa_2proceed.*NONE|2fa.*NONE|skip.*2fa|bypass.*2fa|set2faState.*NONE" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-02 2FA bypass (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-02 2FA bypass (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "auth_skip|required_2fa_2proceed.*NONE|2fa.*NONE|skip.*2fa|bypass.*2fa|set_2fa_state.*none" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-02 2FA bypass (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-02 2FA bypass (Rust)" "No issues found in Rust files"
  fi
fi
