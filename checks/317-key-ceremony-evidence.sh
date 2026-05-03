#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-317
name: Key Ceremony Documentation
description: Verifies that key generation and rotation procedures are documented (key ceremony records, multi-party generation evidence, hardware-attestation logs). Auditors and counterparties expect to see the procedural artifact, not just the code that uses the resulting keys.
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
frameworks: SOC2:TSC-2017:CC6.1, ISO-27001:2022:A.10.1, NIST-CSF:2.0:GV.RM
cwe: 1059
false_positive_rate: high
performance_class: fast
origin: SOC 2 and ISO 27001 audit findings consistently flag absence of key ceremony documentation as a material control gap for crypto custodians.
PRESTON_META

echo "P-317: Key Ceremony Documentation"

SRC="${SOURCE_DIR:-.}"

# Look for ceremony documentation
ceremony=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" --include="*.yaml" \
  -iE 'key[_-]ceremony|key[_-]generation[_-]ceremony|key[_-]ceremony[_-]record|hsm[_-]initialization|seed[_-]ceremony|key[_-]rotation[_-]log|attestation[_-]log|ceremony[_-]witnesses' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

# Look for compliance-template directory referenced
template_dir="${SRC}/compliance-template"
[[ -d "$template_dir" ]] && template_refs=$(find "$template_dir" -iname "*ceremony*" -o -iname "*key-generation*" 2>/dev/null) || template_refs=""

if [[ -n "$ceremony" || -n "$template_refs" ]]; then
  count=$([[ -n "$ceremony" ]] && echo "$ceremony" | wc -l | tr -d ' ' || echo 0)
  record "PASS" "P-317 Key ceremony" "$count file(s) reference key ceremony or rotation documentation"
else
  record "WARN" "P-317 Key ceremony" "No key ceremony documentation found; auditors typically require evidence of key generation procedures" "$(echo "$ceremony" | head -10)"
fi
