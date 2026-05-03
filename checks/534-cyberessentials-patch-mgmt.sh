#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-534
name: Cyber Essentials Patch Management (14-day cycle)
description: Verifies patch-management documentation per UK Cyber Essentials Control 5. High-severity / critical patches must be applied within 14 days.
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
frameworks: UK-Cyber-Essentials:2024:Control-5, CIS-v8:7
false_positive_rate: high
performance_class: fast
origin: UK Cyber Essentials Control 5 — Security Update Management. The 14-day SLA is mandatory for critical patches.
PRESTON_META

echo "P-534: Cyber Essentials Patch Management"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" \
  -iE "patch[_-]management|14[_-]day[_-]patch|security[_-]update[_-]management|critical[_-]patch[_-]SLA|update[_-]cycle" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-534 CE patching" "$(echo "$hits" | wc -l | tr -d ' ') patching reference(s)" \
  || record "WARN" "P-534 CE patching" "No Cyber Essentials patch-management documentation found"
