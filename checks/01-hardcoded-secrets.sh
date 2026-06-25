#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-01
name: Hardcoded Secrets
description: Detects API keys, passwords, AWS credentials, JWT secrets in source code.
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
frameworks: PCI-DSS:4.0:2.2.7, PCI-DSS:4.0:6.3.1, PCI-DSS:4.0:8.6.2, SOC2:TSC-2017:CC6.1, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.4, ISO-27001:2022:5.33, OWASP-API:2023:API8, NIST-CSF:2.0:PR.DS-1, CIS-v8:16.4
PRESTON_META


# P-01: Hardcoded secrets in source code
# Preston used exposed JWT secrets and API keys from the git repo.
# This check scans source code for common secret patterns.

echo "P-01: Hardcoded Secrets"

SRC="${SOURCE_DIR:-.}"

# Patterns that indicate hardcoded secrets
PATTERNS=(
  "password\s*=\s*['\"][^'\"]{8,}"
  "secret\s*=\s*['\"][^'\"]{8,}"
  "api_key\s*=\s*['\"][^'\"]{8,}"
  "auth_token\s*=\s*['\"][^'\"]{8,}"
  "AKIA[0-9A-Z]{16}"
  "-----BEGIN.*PRIVATE KEY-----"
)

found=0
all_hits=""
for pattern in "${PATTERNS[@]}"; do
  hits=$(grep -rn --include="*.java" --include="*.kt" --include="*.ts" --include="*.js" --include="*.py" --include="*.yml" --include="*.yaml" \
    -E "$pattern" "$SRC/Common/src" "$SRC/Registration/src" "$SRC/Client/src" "$SRC/Payments-logic/src" 2>/dev/null \
    | grep -v "test\|Test\|mock\|Mock\|example\|Example\|node_modules\|target\|dist\|\.env\.example" \
    | grep -v "System.getenv\|process.env\|getProperty\|getSecretValue" \
    | grep -v "//\|^\s*\*\|/\*" \
    | grep -v "?secret=\|?api_key=\|+ \"\|URLEncoder\|secretKey\|fxmarketapi" \
    | head -5)
  if [[ -n "$hits" ]]; then
    ((found++))
    all_hits+="$hits"$'\n'
  fi
done

if [[ $found -eq 0 ]]; then
  record "PASS" "P-01 Hardcoded secrets" "No hardcoded secrets found in source"
else
  record "FAIL" "P-01 Hardcoded secrets" "$found secret pattern(s) found in source code" "$all_hits"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "password\s*:?=\s*\"|secret\s*:?=\s*\"|apiKey\s*:?=\s*\"" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-01 Hardcoded secrets (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-01 Hardcoded secrets (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "password\s*=\s*\"|secret\s*=\s*\"|api_key\s*=\s*\"" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-01 Hardcoded secrets (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-01 Hardcoded secrets (Rust)" "No issues found in Rust files"
  fi
fi
