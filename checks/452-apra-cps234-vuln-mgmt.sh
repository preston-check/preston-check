#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-452
name: APRA CPS 234 Vulnerability and Threat Management
description: Verifies vulnerability and threat management processes per APRA CPS 234 paragraphs 25-29 — testing program, third-party reviews, prompt remediation of identified weaknesses.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: APRA-CPS234:2019:para25, NIST-CSF:2.0:DE.CM, CIS-v8:7.1
false_positive_rate: high
performance_class: fast
origin: APRA CPS 234 paragraphs 25-29 — vulnerability and threat management.
PRESTON_META

echo "P-452: CPS 234 Vulnerability and Threat Management"

SRC="${SOURCE_DIR:-.}"
vm=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "vulnerability[_-]management|threat[_-]management|VA[_-]VAPT|third[_-]party[_-]review|external[_-]assessment" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$vm" ]] && record "PASS" "P-452 CPS 234 vuln mgmt" "$(echo "$vm" | wc -l | tr -d ' ') vuln/threat mgmt reference(s)" \
  || record "WARN" "P-452 CPS 234 vuln mgmt" "No vulnerability/threat management documentation found"
