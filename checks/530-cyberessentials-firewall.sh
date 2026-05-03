#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-530
name: Cyber Essentials Firewall and Boundary Devices
description: Verifies firewall and boundary-device configuration documentation per UK Cyber Essentials Control 1. Required for UK central-government supply chain and increasingly cited as a baseline by UK fintechs.
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
frameworks: UK-Cyber-Essentials:2024:Control-1, NIST-CSF:2.0:PR.AC, CIS-v8:13
false_positive_rate: high
performance_class: fast
origin: UK National Cyber Security Centre Cyber Essentials scheme.
PRESTON_META

echo "P-530: Cyber Essentials Firewall"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.tf" --include="*.yml" \
  -iE "cyber[_-]essentials|boundary[_-]firewall|perimeter[_-]firewall|UK[_-]NCSC|firewall[_-]ruleset" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-530 CE firewall" "$(echo "$hits" | wc -l | tr -d ' ') firewall/boundary reference(s)" \
  || record "WARN" "P-530 CE firewall" "No Cyber Essentials firewall/boundary documentation found"
