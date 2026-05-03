#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-401
name: DORA ICT Incident Classification and Reporting
description: Verifies that the organization can classify ICT-related incidents per DORA Article 18 criteria (impact, criticality, duration, geographic spread, data losses, economic impact) and has a process to report major incidents to competent authorities within DORA-mandated timelines (4 hours initial, 72 hours intermediate, 1 month final).
category: compliance-evidence
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.2.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: DORA:2025:Art.17, DORA:2025:Art.18, DORA:2025:Art.19, NIST-CSF:2.0:RS.CO, ISO-27001:2022:5.24
false_positive_rate: high
performance_class: fast
origin: DORA Article 17-19 mandates ICT incident classification and structured reporting to competent authorities. EU regulators have published RTS specifying exact timelines.
PRESTON_META

echo "P-401: DORA Incident Reporting"

SRC="${SOURCE_DIR:-.}"

ir_refs=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" --include="*.json" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'DORA[_-]incident|incident[_-]classification|major[_-]incident|incident[_-]report[_-]timeline|4[_-]hour[_-]notification|competent[_-]authority|EU[_-]incident[_-]report|RTS[_-]incident' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

# General IR references
ir_general=$(grep -rln --include="*.md" --include="*.txt" \
  -iE 'incident[_-]response[_-]plan|incident[_-]reporting[_-]process|escalation[_-]procedure' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -n "$ir_refs" ]]; then
  count=$(echo "$ir_refs" | wc -l | tr -d ' ')
  record "PASS" "P-401 DORA incident reporting" "$count reference(s) to DORA-aligned incident classification/reporting"
elif [[ -n "$ir_general" ]]; then
  count=$(echo "$ir_general" | wc -l | tr -d ' ')
  record "WARN" "P-401 DORA incident reporting" "$count generic IR doc(s); ensure DORA-specific timelines and classification criteria"
else
  record "FAIL" "P-401 DORA incident reporting" "No incident response or DORA-aligned reporting documentation found"
fi
