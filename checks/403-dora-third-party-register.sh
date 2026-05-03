#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-403
name: DORA ICT Third-Party Risk Register
description: Verifies presence of an ICT third-party register per DORA Article 28 — comprehensive list of all ICT service providers, their criticality, contract terms, exit strategies, sub-contractor chains, and concentration risk indicators. Required for EU regulator on demand.
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
frameworks: DORA:2025:Art.28, DORA:2025:Art.30, NIST-CSF:2.0:GV.SC, ISO-27001:2022:5.19, CIS-v8:15.1
false_positive_rate: high
performance_class: fast
origin: DORA Articles 28-30 require an up-to-date register of ICT third-party service providers, with explicit treatment of cloud and CTPP (Critical Third-Party Provider) dependencies.
PRESTON_META

echo "P-403: DORA Third-Party Register"

SRC="${SOURCE_DIR:-.}"

register_refs=$(find "$SRC" -type f \( -iname "*third-party*" -o -iname "*vendor-register*" -o -iname "*ict-register*" -o -iname "*supplier-register*" -o -iname "*ctpp*" -o -iname "*concentration*" \) 2>/dev/null \
  | grep -vE 'node_modules' || true)

vendor_docs=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" --include="*.json" \
  -iE 'third[_-]party[_-]register|ICT[_-]register|vendor[_-]register|supplier[_-]register|CTPP|critical[_-]third[_-]party|concentration[_-]risk|exit[_-]strategy[_-]vendor' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

count_files=$([[ -n "$register_refs" ]] && echo "$register_refs" | wc -l | tr -d ' ' || echo 0)
count_docs=$([[ -n "$vendor_docs" ]] && echo "$vendor_docs" | wc -l | tr -d ' ' || echo 0)

if [[ ${count_files:-0} -gt 0 || ${count_docs:-0} -gt 0 ]]; then
  record "PASS" "P-403 DORA third-party register" "$count_files file(s) + $count_docs doc reference(s) to ICT third-party register"
else
  record "FAIL" "P-403 DORA third-party register" "No ICT third-party / vendor register found" "$(echo "$vendor_docs" | head -10)"
fi
