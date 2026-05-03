#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-540
name: GLBA Safeguards Rule Information Security Program
description: Verifies a written Information Security Program documenting the safeguards required by the FTC Safeguards Rule (16 CFR 314), as amended in 2023. Required for any non-bank financial institution.
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
frameworks: GLBA-Safeguards:16CFR314, NIST-CSF:2.0:GV.PO, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: FTC Safeguards Rule, amended December 2021 (effective June 2023). Applies broadly to non-bank financial institutions.
PRESTON_META

echo "P-540: GLBA Safeguards Rule"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "GLBA|gramm[_-]leach[_-]bliley|safeguards[_-]rule|16[_-]CFR[_-]314|FTC[_-]safeguards" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-540 GLBA safeguards" "$(echo "$hits" | wc -l | tr -d ' ') GLBA reference(s)" \
  || record "WARN" "P-540 GLBA safeguards" "No GLBA Safeguards Rule documentation found"
