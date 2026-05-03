#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-441
name: MAS TRM Cyber Hygiene Notice
description: Verifies adherence to MAS Cyber Hygiene Notice (CH Notice 6 categories) — security patches, hardening, network perimeter, malware protection, MFA on admin, customer data security. Mandatory for Singapore-licensed FIs since August 2020.
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
frameworks: MAS-CHN:2020, NIST-CSF:2.0:PR.IP, ISO-27001:2022:8.8
false_positive_rate: high
performance_class: fast
origin: MAS Cyber Hygiene Notice (Notice 655, August 2020) — six mandatory cyber hygiene categories.
PRESTON_META

echo "P-441: MAS Cyber Hygiene Notice"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" \
  -iE "MAS[_-]cyber[_-]hygiene|cyber[_-]hygiene[_-]notice|CH[_-]notice|MAS notice 655|six[_-]cyber[_-]hygiene" "$SRC" 2>/dev/null | grep -v node_modules || true)
patch_mgmt=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" \
  -iE "patch[_-]management|hardening[_-]baseline|perimeter[_-]security|admin[_-]mfa|customer[_-]data[_-]security" "$SRC" 2>/dev/null | grep -v node_modules || true)
if [[ -n "$hits" ]]; then
  record "PASS" "P-441 MAS cyber hygiene" "$(echo "$hits" | wc -l | tr -d ' ') reference(s) to MAS Cyber Hygiene"
elif [[ -n "$patch_mgmt" ]]; then
  record "WARN" "P-441 MAS cyber hygiene" "Generic hygiene refs present; ensure 6-category coverage per MAS Notice 655"
else
  record "WARN" "P-441 MAS cyber hygiene" "No MAS Cyber Hygiene documentation found"
fi
