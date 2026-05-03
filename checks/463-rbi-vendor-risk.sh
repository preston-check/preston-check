#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-463
name: RBI Third-Party / Vendor Risk Management
description: Verifies third-party risk management per RBI Cyber Security Framework and the 2023 Outsourcing Master Direction — vendor due diligence, contract requirements, ongoing monitoring, exit strategies.
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
frameworks: RBI-CSF:2024:VRM, RBI-OMD:2023, NIST-CSF:2.0:GV.SC, ISO-27001:2022:5.19
false_positive_rate: high
performance_class: fast
origin: RBI CSF + Master Direction on Outsourcing of IT Services 2023.
PRESTON_META

echo "P-463: RBI Vendor Risk Management"

SRC="${SOURCE_DIR:-.}"
vrm=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "vendor[_-]risk|third[_-]party[_-]risk|outsourcing[_-]direction|RBI[_-]outsourcing|due[_-]diligence|exit[_-]strategy" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$vrm" ]] && record "PASS" "P-463 RBI vendor risk" "$(echo "$vrm" | wc -l | tr -d ' ') vendor risk reference(s)" \
  || record "WARN" "P-463 RBI vendor risk" "No vendor / third-party risk management documentation found"
