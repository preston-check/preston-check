#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-09
name: Audit Trail
description: Checks for DB triggers, append-only enforcement on financial tables.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
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
  "prevent.*delete\|BEFORE DELETE.*RAISE\|append.only\|DELETE.*CANCELLED" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$delete_prevention" ]]; then
  record "PASS" "P-09 Append-only ledger" "Delete prevention on financial tables found"
else
  record "WARN" "P-09 Append-only ledger" "No delete prevention on financial tables found" "$(echo "$delete_prevention" | head -10)"
fi
