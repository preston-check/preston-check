#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-03
name: Information Leakage
description: Detects exception messages, sensitive fields, and internal data in API responses.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.2.4.3, SOC2:TSC-2017:CC7.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.12, OWASP-API:2023:API3, NIST-CSF:2.0:PR.DS-2, CIS-v8:3.12
PRESTON_META


# P-03: Information leakage in API responses
# Preston's session polling returned Vouched keys, full fee structure,
# all permissions, and internal IDs. API responses should minimize data exposure.

echo "P-03: Information Leakage"

SRC="${SOURCE_DIR:-.}"

# Check for exception messages returned to client
exception_leak=$(grep -rn --include="*.java" \
  "e\.getMessage()\|e\.toString()\|e\.getStackTrace()\|e\.printStackTrace()" \
  "$SRC" 2>/dev/null \
  | grep -i "return\|response\|body\|payload\|toJackson\|json" \
  | grep -v "log\.\|LOG\.\|test\|Test\|target\|node_modules" \
  | head -10)

if [[ -z "$exception_leak" ]]; then
  record "PASS" "P-03 Exception leakage" "No exception messages in API responses"
else
  count=$(echo "$exception_leak" | wc -l)
  record "WARN" "P-03 Exception leakage" "$count potential exception message leaks in responses" "$(echo "$exception_leak" | head -10)"
fi

# Check for sensitive fields in serialized objects without @JsonIgnore
sensitive_fields=$(grep -rn --include="*.java" \
  "private.*password\|private.*secret\|private.*token\|private.*apiKey\|private.*salt" \
  "$SRC" 2>/dev/null \
  | grep -v "@JsonIgnore\|@JsonProperty.*access.*WRITE\|test\|Test\|target" \
  | grep -v "log\.\|LOG\.\|transient" \
  | head -10)

if [[ -z "$sensitive_fields" ]]; then
  record "PASS" "P-03 Sensitive field exposure" "Sensitive fields properly hidden"
else
  count=$(echo "$sensitive_fields" | wc -l)
  record "WARN" "P-03 Sensitive field exposure" "$count sensitive fields may be serialized (check @JsonIgnore)" "$(echo "$sensitive_fields" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "fmt\.Print|fmt\.Println|fmt\.Fprintf|log\.Print" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-03 Information leakage (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-03 Information leakage (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "println!|eprintln!|dbg!|print!" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-03 Information leakage (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-03 Information leakage (Rust)" "No issues found in Rust files"
  fi
fi
