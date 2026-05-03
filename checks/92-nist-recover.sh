#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-92
name: NIST Recover
description: Verifies recovery planning, recovery communications.
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
frameworks: ISO-27001:2022:5.30
PRESTON_META


# P-92: NIST CSF 2.0 Recover Function — Recovery Planning & Communication
echo "P-92: NIST CSF Recover"
SRC="${SOURCE_DIR:-.}"

# RC.RP — Recovery Plan Execution
recovery_plan=$(find "$SRC" -maxdepth 5 \( \
  -iname "*recovery*plan*" -o -iname "*disaster*recovery*" -o -iname "*business*continuity*" \
  -o -iname "*dr*plan*" -o -iname "*bcp*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
recovery_code=$(grep -rn --include="*.sh" --include="*.yml" --include="*.md" \
  "failover\|switchover\|recovery.*procedure\|restore.*from.*backup\|rto\|rpo\|disaster.*recovery" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$recovery_plan" || -n "$recovery_code" ]]; then
  record "PASS" "P-92 Recovery planning" "Recovery/DR planning evidence found"
else
  record "WARN" "P-92 Recovery planning" "No disaster recovery plan (NIST RC.RP)"
fi

# RC.CO — Recovery Communication
comm=$(grep -rn --include="*.md" --include="*.yml" --include="*.java" --include="*.ts" \
  "status.*page\|incident.*communication\|customer.*notification\|outage.*notification\|stakeholder.*notify" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules\|test\|Test" | head -3)
comm_doc=$(find "$SRC" -maxdepth 5 \( -iname "*communication*plan*" -o -iname "*notification*template*" -o -iname "*status*page*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
if [[ -n "$comm" || -n "$comm_doc" ]]; then
  record "PASS" "P-92 Recovery communication" "Recovery communication/notification patterns found"
else
  record "WARN" "P-92 Recovery communication" "No recovery communication plan — how do you notify customers during an outage?"
fi
