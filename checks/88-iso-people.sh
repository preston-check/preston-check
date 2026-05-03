#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-88
name: Iso People
description: Iso People security check (see COMPLIANCE_MAPPING.md for details).
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-88: ISO 27001 People Controls (A.6.x) Evidence
# Checks for screening, training, disciplinary, and termination procedure artifacts.
echo "P-88: ISO 27001 People Controls"
SRC="${SOURCE_DIR:-.}"

found=0

# A.6.1 — Screening (background checks)
screening=$(find "$SRC" -maxdepth 5 \( -iname "*background*check*" -o -iname "*screening*" -o -iname "*vetting*" -o -iname "*onboard*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$screening" ]] && found=$((found + 1))

# A.6.3 — Awareness/training
training=$(find "$SRC" -maxdepth 5 \( -iname "*training*" -o -iname "*awareness*" -o -iname "*security*education*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
training_ref=$(grep -rn --include="*.md" --include="*.yml" \
  "training.*program\|security.*awareness\|phishing.*simulation\|knowbe4\|annual.*training" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$training" || -n "$training_ref" ]] && found=$((found + 1))

# A.6.5 — Responsibilities after termination
termination=$(find "$SRC" -maxdepth 5 \( -iname "*offboard*" -o -iname "*termination*" -o -iname "*exit*procedure*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
term_code=$(grep -rn --include="*.java" --include="*.ts" \
  "deactivate.*user\|disable.*account\|revoke.*access\|offboard\|exit.*checklist" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -1)
[[ -n "$termination" || -n "$term_code" ]] && found=$((found + 1))

# A.6.7 — Remote working
remote=$(grep -rn --include="*.md" --include="*.yml" \
  "remote.*work\|work.*from.*home\|vpn.*policy\|remote.*access.*policy" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$remote" ]] && found=$((found + 1))

if [[ $found -ge 3 ]]; then
  record "PASS" "P-88 ISO people controls" "$found/4 people control evidence found"
elif [[ $found -ge 1 ]]; then
  record "WARN" "P-88 ISO people controls" "$found/4 — need: screening/onboarding, training, offboarding, remote work policy"
else
  record "WARN" "P-88 ISO people controls" "No people control evidence — create compliance/ directory with HR security procedures"
fi
