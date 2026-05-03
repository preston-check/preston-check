#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-525
name: NIS2 Essential Entity Designation
description: Verifies documentation of NIS2 Directive (EU 2022/2555) essential or important entity designation. NIS2 covers digital infrastructure, finance, health, public administration, manufacturing, and other critical sectors with cybersecurity risk-management obligations.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIS2:2022/2555:Art.21, NIST-CSF:2.0:GV.RM
false_positive_rate: high
performance_class: fast
origin: NIS2 Directive entered into force October 2024; member-state transposition deadline October 2025.
PRESTON_META

echo "P-525: NIS2 Entity Designation"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "NIS2|NIS[_-]2|essential[_-]entity|important[_-]entity|EU[_-]2022/2555|network[_-]information[_-]security" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-525 NIS2 entity" "$(echo "$hits" | wc -l | tr -d ' ') NIS2 reference(s)" \
  || record "WARN" "P-525 NIS2 entity" "No NIS2 entity-designation documentation found"
