#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-75
name: Audit Immutability
description: Detects audit triggers, append-only enforcement, actor attribution, retention.
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
frameworks: PCI-DSS:4.0:10.3.1, PCI-DSS:4.0:10.3.2, SOC2:TSC-2017:CC4.1, SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.15, NIST-CSF:2.0:PR.PT-1, CIS-v8:8.5
PRESTON_META


# P-75: Financial Audit Trail Immutability
# Audit logs must be tamper-proof, append-only, with cryptographic integrity.
# Regulators require provable audit trails for every financial event.
echo "P-75: Audit Immutability"
SRC="${SOURCE_DIR:-.}"

# Check for audit table existence and trigger protection
audit_triggers=$(grep -rn --include="*.sql" --include="*.java" \
  "audit.*trigger\|CREATE TRIGGER.*audit\|audit_log\|audit_trail\|request_log\|BEFORE DELETE.*audit\|BEFORE UPDATE.*audit" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -5)
if [[ -n "$audit_triggers" ]]; then
  record "PASS" "P-75 Audit triggers" "Audit table triggers/protection found"
else
  record "WARN" "P-75 Audit triggers" "No audit table triggers — audit logs must be protected from deletion/modification" "$(echo "$audit_triggers" | head -10)"
fi

# Check for audit log append-only enforcement
audit_immutable=$(grep -rn --include="*.sql" --include="*.java" \
  "prevent_delete\|prevent_update\|raise.*exception.*delete\|raise.*exception.*update\|INSTEAD OF DELETE\|NO DELETE" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$audit_immutable" ]]; then
  record "PASS" "P-75 Append-only audit" "Audit log append-only enforcement found"
else
  record "WARN" "P-75 Append-only audit" "No append-only enforcement on audit logs — logs must be immutable" "$(echo "$audit_immutable" | head -10)"
fi

# Check for audit log completeness (actor, action, timestamp, before/after)
audit_fields=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "actor\|performed_by\|changed_by\|user_id.*audit\|old_value\|new_value\|before_state\|after_state" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$audit_fields" ]]; then
  record "PASS" "P-75 Audit completeness" "Audit records include actor and state change fields"
else
  record "WARN" "P-75 Audit completeness" "Audit records may lack actor attribution or before/after state" "$(echo "$audit_fields" | head -10)"
fi

# Check for audit log integrity (hash chain, signatures, or external store)
audit_integrity=$(grep -rn --include="*.java" --include="*.ts" \
  "audit.*hash\|log.*hash\|chain.*hash\|merkle\|tamper.*proof\|log.*integrity\|write.*once\|worm\|cloudwatch.*log\|cloudtrail" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$audit_integrity" ]]; then
  record "PASS" "P-75 Audit integrity" "Audit log integrity mechanism found (hash chain, external store, or WORM)"
else
  record "WARN" "P-75 Audit integrity" "No cryptographic audit log integrity — consider hash chaining or CloudTrail for tamper detection" "$(echo "$audit_integrity" | head -10)"
fi

# Check for audit retention policy
audit_retention=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" --include="*.yml" \
  "audit.*retention\|log.*retention\|archive.*audit\|purge.*audit\|audit.*partition\|7.*year\|5.*year" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$audit_retention" ]]; then
  record "PASS" "P-75 Audit retention" "Audit retention policy found"
else
  record "WARN" "P-75 Audit retention" "No audit retention policy — regulators require 5-7 year retention for financial records" "$(echo "$audit_retention" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "audit.*log|AuditEvent|audit\.Log|auditLog|audit_trigger|audit_trail|prevent_delete|prevent_update|audit.*hash|tamper.*proof|audit.*retention" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-75 Audit Immutability (Go)" "Audit log / immutability patterns found in Go code"
  else
    record "WARN" "P-75 Audit Immutability (Go)" "No audit log, append-only enforcement, or integrity patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "audit_log|AuditLog|AuditEvent|audit_trigger|audit_trail|prevent_delete|prevent_update|audit.*hash|tamper.*proof|audit.*retention" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-75 Audit Immutability (Rust)" "Audit log / immutability patterns found in Rust code"
  else
    record "WARN" "P-75 Audit Immutability (Rust)" "No audit log, append-only enforcement, or integrity patterns found in Rust files"
  fi
fi
