#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-80
name: Financial Event Sourcing
description: Detects event log immutability, history tables, point-in-time queries, lineage.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:10.2, SOC2:TSC-2017:CC4.1, ISO-27001:2022:8.15, NIST-CSF:2.0:PR.PT-1
PRESTON_META


# P-80: Financial Event Sourcing & Reconstruction
# Every financial state must be reconstructable from the event log.
# If the current balance cannot be derived by replaying events, the system is compromised.
echo "P-80: Financial Event Sourcing"
SRC="${SOURCE_DIR:-.}"

# Check for event-driven architecture patterns
event_sourcing=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "event.*source\|event.*store\|event.*log\|event.*stream\|replay.*event\|reconstruct\|rehydrat\|journal" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$event_sourcing" ]]; then
  record "PASS" "P-80 Event sourcing" "Event sourcing/journaling patterns found"
else
  record "WARN" "P-80 Event sourcing" "No event sourcing — consider journaling all financial mutations for reconstruction" "$(echo "$event_sourcing" | head -10)"
fi

# Check for transaction history completeness (every state change logged)
history_log=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "history.*table\|_history\|_audit\|_log.*table\|change.*log\|state.*change.*log\|version.*column" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$history_log" ]]; then
  count=$(echo "$history_log" | wc -l | tr -d ' ')
  record "PASS" "P-80 History tables" "$count history/audit table patterns found"
else
  record "WARN" "P-80 History tables" "No history tables — every financial entity should have a change history" "$(echo "$history_log" | head -10)"
fi

# Check for point-in-time query capability
point_in_time=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "as_of\|point.*in.*time\|temporal\|valid_from\|valid_to\|effective_date\|snapshot\|balance.*at" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$point_in_time" ]]; then
  record "PASS" "P-80 Point-in-time" "Point-in-time query capability found"
else
  record "WARN" "P-80 Point-in-time" "No point-in-time query — should be able to reconstruct state at any past moment" "$(echo "$point_in_time" | head -10)"
fi

# Check for data lineage (where did this balance come from?)
lineage=$(grep -rn --include="*.java" --include="*.ts" --include="*.sql" \
  "lineage\|provenance\|source.*transaction\|parent.*transaction\|linked.*transaction\|trace.*id\|correlation.*id" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$lineage" ]]; then
  record "PASS" "P-80 Data lineage" "Transaction lineage/correlation tracking found"
else
  record "WARN" "P-80 Data lineage" "No transaction lineage — should trace every balance back to its origin" "$(echo "$lineage" | head -10)"
fi
