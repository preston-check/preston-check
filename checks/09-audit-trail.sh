#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-09
name: Audit Trail
description: Checks for DB triggers, append-only enforcement on financial tables.
category: code-scan
severity: high
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:10.2, PCI-DSS:4.0:10.3, SOC2:TSC-2017:CC4.1, SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.15, ISO-27001:2022:8.17, NIST-CSF:2.0:DE.CM-3, CIS-v8:8.2
PRESTON_META


# P-09: Audit trail completeness
# Every sensitive operation must have an audit trail that cannot be altered.

echo "P-09: Audit Trail"

SRC="${SOURCE_DIR:-.}"

# Check for audit logging on sensitive tables
audit_triggers=$(grep -rn --include="*.sql" \
  --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" \
  --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" \
  "audit_trigger\|CREATE TRIGGER.*audit\|AFTER.*INSERT.*UPDATE.*DELETE" \
  "$SRC/db" 2>/dev/null \
  | grep -v "test\|mock" \
  | head -10)

if [[ -n "$audit_triggers" ]]; then
  count=$(echo "$audit_triggers" | wc -l)
  record "PASS" "P-09 DB audit triggers" "$count audit trigger definitions found"
else
  record "WARN" "P-09 DB audit triggers" "No database audit triggers found" "$(echo "$audit_triggers" | head -10)"
fi

# Check for append-only enforcement (prevent DELETE on financial tables)
delete_prevention=$(grep -rn --include="*.sql" --include="*.java" \
  --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" \
  --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" \
  "prevent.*delete\|BEFORE DELETE.*RAISE\|append.only\|DELETE.*CANCELLED" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test" \
  | head -5)

if [[ -n "$delete_prevention" ]]; then
  record "PASS" "P-09 Append-only ledger" "Delete prevention on financial tables found"
else
  record "WARN" "P-09 Append-only ledger" "No delete prevention on financial tables found" "$(echo "$delete_prevention" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "auditLog|AuditEvent|audit\.Log" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-09 Audit trail (Go)" "$_go_count audit log instance(s) found in Go code"
  else
    record "WARN" "P-09 Audit trail (Go)" "No audit logging patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "audit_log|AuditLog|AuditEvent|tracing::info.*audit" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-09 Audit trail (Rust)" "$_rs_count audit log instance(s) found in Rust code"
  else
    record "WARN" "P-09 Audit trail (Rust)" "No audit logging patterns found in Rust files"
  fi
fi
