#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-358
name: CryptoCurrency Security Standard (CCSS) Evidence
description: Verifies the existence of CCSS Level 1+ compliance evidence: key/seed generation procedures, secure key storage attestations, key usage policies, key holder grant/revoke procedures, key compromise/incident response, and operational walk-through documentation. CCSS v9.0 (Dec 2024) is the de facto crypto-custody compliance framework.
category: compliance-evidence
severity: low
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: CCSS:9.0:Level1, CCSS:9.0:Level2, CCSS:9.0:Level3
cwe: 1059
false_positive_rate: high
performance_class: fast
origin: CCSS v9.0 published December 2024 by the CryptoCurrency Certification Consortium (C4); standard adopted by major qualified custodians and exchange auditors.
PRESTON_META

echo "P-358: CCSS Compliance Evidence"

SRC="${SOURCE_DIR:-.}"

# Look for CCSS-required documentation
ccss_docs=$(find "$SRC" -type f \( -iname "*.md" -o -iname "*.pdf" -o -iname "*.docx" -o -iname "*.txt" \) 2>/dev/null \
  | grep -iE 'ccss|key[_-](generation|storage|usage|compromise|holder)|policy|operational[_-]walkthrough|key[_-]ceremony|incident[_-]response' \
  | grep -vE 'node_modules|/test/' || true)

# Or compliance-template directory
template_dir="${SRC}/compliance-template"
if [[ -d "$template_dir" ]]; then
  ccss_in_template=$(find "$template_dir" -iname "*ccss*" -o -iname "*key-management*" -o -iname "*operational*" 2>/dev/null)
else
  ccss_in_template=""
fi

if [[ -n "$ccss_docs" || -n "$ccss_in_template" ]]; then
  count=$([[ -n "$ccss_docs" ]] && echo "$ccss_docs" | wc -l | tr -d ' ' || echo 0)
  template_count=$([[ -n "$ccss_in_template" ]] && echo "$ccss_in_template" | wc -l | tr -d ' ' || echo 0)
  record "PASS" "P-358 CCSS evidence" "$count CCSS-relevant doc(s); $template_count compliance-template entry(ies)"
else
  record "WARN" "P-358 CCSS evidence" "No CCSS Level 1+ documentation evidence found (key generation, storage, usage policies, ceremony records)" "$(echo "$ccss_in_template" | head -10)"
fi
