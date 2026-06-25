#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-42
name: CI/CD Security
description: Checks credentials in scripts, curl/bash, SSL disabled.
category: infra-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.5.3, PCI-DSS:4.0:6.5.4, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.31, NIST-CSF:2.0:PR.IP-3, CIS-v8:16.7
PRESTON_META


# P-42: CI/CD Pipeline Security
echo "P-42: CI/CD Security"
SRC="${SOURCE_DIR:-.}"
creds_scripts=$(grep -rn --include="*.sh" "password\|secret\|api_key\|AWS_ACCESS\|AWS_SECRET" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -i "deploy\|build\|setup\|install" | grep -v "getenv\|System\|test\|example\|#\|echo\|\${\|export" | head -5)
if [[ -z "$creds_scripts" ]]; then record "PASS" "P-42 No creds in scripts" "No credentials in deploy/build scripts"; else count=$(echo "$creds_scripts" | wc -l); record "WARN" "P-42 Creds in scripts" "$count deploy/build scripts may contain credentials"; fi
curl_bash=$(grep -rn --include="*.sh" "curl.*|.*bash\|curl.*|.*sh\|wget.*|.*bash" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "#\|test\|Test" | head -3)
if [[ -z "$curl_bash" ]]; then record "PASS" "P-42 No curl|bash" "No curl-pipe-to-bash patterns"; else record "FAIL" "P-42 curl|bash" "curl|bash pattern found — supply chain risk"; fi
ssl_skip=$(grep -rn --include="*.sh" --include="*.java" "insecure\|ssl.*verify.*false\|no-check-certificate\|trustAllCerts\|ALLOW_ALL" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#\|self.*signed\|buildSelfSigned" | head -3)
if [[ -z "$ssl_skip" ]]; then record "PASS" "P-42 SSL verification" "No SSL verification bypasses"; else record "WARN" "P-42 SSL verification" "SSL verification disabled in some scripts"; fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "InsecureSkipVerify\s*:\s*true" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-42 TLS Skip Verify (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-42 TLS Skip Verify (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "danger_accept_invalid_certs|DANGER_ACCEPT_INVALID" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-42 TLS Skip Verify (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-42 TLS Skip Verify (Rust)" "No issues found in Rust files"
  fi
fi
