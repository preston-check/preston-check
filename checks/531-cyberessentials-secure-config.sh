#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-531
name: Cyber Essentials Secure Configuration
description: Verifies secure configuration baselines per UK Cyber Essentials Control 2. Includes hardening baselines, removal of default accounts, and disabling unnecessary services.
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
frameworks: UK-Cyber-Essentials:2024:Control-2, CIS-v8:4.1, NIST-CSF:2.0:PR.IP
false_positive_rate: high
performance_class: fast
origin: UK Cyber Essentials Control 2 — Secure Configuration.
PRESTON_META

echo "P-531: Cyber Essentials Secure Config"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" --include="*.tf" \
  -iE "hardening[_-]baseline|secure[_-]configuration|default[_-]password[_-]removed|CIS[_-]benchmark|disable[_-]unused[_-]service" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-531 CE secure config" "$(echo "$hits" | wc -l | tr -d ' ') secure-config reference(s)" \
  || record "WARN" "P-531 CE secure config" "No Cyber Essentials secure-configuration documentation found"
