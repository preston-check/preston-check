#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-405
name: DORA Digital Operational Resilience Testing Program
description: Verifies an annual digital operational resilience testing program per DORA Article 24 — vulnerability assessments, network security assessments, gap analyses, source code reviews, and scenario-based testing of critical-or-important functions. Distinct from TLPT (P-402) which is the threat-led variant.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.2.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: DORA:2025:Art.24, DORA:2025:Art.25, NIST-CSF:2.0:ID.RA, CIS-v8:18.1
false_positive_rate: high
performance_class: fast
origin: DORA Article 24 establishes a tiered testing program; Article 25 details the methodologies. Annual cadence for vulnerability assessments and scenario testing.
PRESTON_META

echo "P-405: DORA Resilience Testing"

SRC="${SOURCE_DIR:-.}"

testing=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" \
  -iE 'resilience[_-]testing|operational[_-]resilience[_-]test|DORA[_-]testing|annual[_-]vulnerability[_-]assessment|scenario[_-]based[_-]test|gap[_-]analysis[_-]testing|digital[_-]resilience' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

vuln_scan_evidence=$(grep -rln --include="*.md" --include="*.yml" \
  -iE 'vulnerability[_-]scan[_-]schedule|sast[_-]config|dast[_-]config|scan[_-]report' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -n "$testing" ]]; then
  count=$(echo "$testing" | wc -l | tr -d ' ')
  record "PASS" "P-405 DORA resilience testing" "$count reference(s) to operational resilience testing program"
elif [[ -n "$vuln_scan_evidence" ]]; then
  record "WARN" "P-405 DORA resilience testing" "Generic vuln scan references; ensure DORA-aligned annual program with scenario-based testing"
else
  record "WARN" "P-405 DORA resilience testing" "No documented DORA resilience-testing program found"
fi
