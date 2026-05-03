#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-406
name: DORA Threat Intelligence Sharing Arrangements
description: Verifies the entity participates in or has documented arrangements for cyber threat intelligence sharing per DORA Article 45. ISACs, FS-ISAC, MELANI, ENISA platforms, or bilateral peer arrangements all qualify; the requirement is the documented practice of sharing actionable threat indicators.
category: compliance-evidence
severity: low
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.2.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: DORA:2025:Art.45, NIST-CSF:2.0:ID.RA-2, ISO-27001:2022:5.5
false_positive_rate: high
performance_class: fast
origin: DORA Article 45 establishes arrangements for the exchange of cyber threat information among financial entities, with reference to Directive (EU) 2016/680 data protection.
PRESTON_META

echo "P-406: DORA Threat Intelligence Sharing"

SRC="${SOURCE_DIR:-.}"

sharing=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" \
  -iE 'threat[_-]intel[_-]sharing|ISAC|FS-ISAC|MELANI|ENISA|cyber[_-]threat[_-]intel[_-]exchange|threat[_-]intelligence[_-]platform|TIP[_-]integration' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -n "$sharing" ]]; then
  count=$(echo "$sharing" | wc -l | tr -d ' ')
  record "PASS" "P-406 DORA threat intel sharing" "$count reference(s) to threat-intel sharing arrangements"
else
  record "WARN" "P-406 DORA threat intel sharing" "No documented threat-intel sharing arrangements (DORA Art. 45)" "$(echo "$sharing" | head -10)"
fi
