#!/bin/bash
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
  record "WARN" "P-09 DB audit triggers" "No database audit triggers found"
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
  record "WARN" "P-09 Append-only ledger" "No delete prevention on financial tables found"
fi
