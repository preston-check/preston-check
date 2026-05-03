#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-421
name: OWASP Mobile M2 — Inadequate Supply Chain Security
description: Detects mobile supply chain risks — third-party SDKs without integrity verification, unpinned mobile dependencies, missing Play Integrity / DeviceCheck attestation.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-MAS:2024:M2, NIST-CSF:2.0:GV.SC, ISO-27001:2022:5.19
false_positive_rate: high
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M2 — Inadequate Supply Chain Security.
PRESTON_META

echo "P-421: Mobile Supply Chain Security"

SRC="${SOURCE_DIR:-.}"
attest=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "PlayIntegrityApi|DeviceCheck|attestation|App[_-]Attest|SafetyNet|integrityToken" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$attest" ]] && record "PASS" "P-421 mobile supply chain" "$(echo "$attest" | wc -l | tr -d ' ') attestation reference(s)" \
  || record "WARN" "P-421 mobile supply chain" "No Play Integrity / DeviceCheck / App Attest references found"
