#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-543
name: GLBA Customer Information Encryption
description: Detects code paths that handle customer information (covered "personally identifiable financial information") and verifies encryption at rest references. GLBA Safeguards Rule 16 CFR 314.4(c)(3) requires encryption of all customer information held by the institution.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: GLBA-Safeguards:16CFR314.4.c, NIST-CSF:2.0:PR.DS-1, PCI-DSS:4.0:3.5
cwe: 311
false_positive_rate: medium
performance_class: fast
origin: GLBA Safeguards Rule customer-information encryption requirement.
PRESTON_META

echo "P-543: GLBA Customer Info Encryption"

SRC="${SOURCE_DIR:-.}"
strong=$(grep -rln --include="*.java" --include="*.kt" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.rb" --include="*.cs" --include="*.php" \
  -iE "AES[_-]GCM|ChaCha20[_-]Poly1305|customer[_-]info[_-]encrypt|PII[_-]at[_-]rest|encrypt[_-]customer" "$SRC" 2>/dev/null | grep -v node_modules || true)
weak=$(grep -rln --include="*.yml" --include="*.yaml" --include="*.tf" --include="*.json" \
  -iE "encryption\s*:\s*false|encrypted\s*[:=]\s*false|server[_-]side[_-]encryption\s*[:=]\s*[\"']?disabled" "$SRC" 2>/dev/null | grep -v node_modules || true)
if [[ -n "$weak" ]]; then
  sample=$(echo "$weak" | head -10)
  record "FAIL" "P-543 GLBA encryption" "$(echo "$weak" | wc -l | tr -d ' ') encryption-disabled configuration(s)" "$sample"
elif [[ -n "$strong" ]]; then
  record "PASS" "P-543 GLBA encryption" "$(echo "$strong" | wc -l | tr -d ' ') strong-encryption reference(s) for customer info"
else
  record "WARN" "P-543 GLBA encryption" "No customer-info encryption references found; verify GLBA encryption requirement"
fi
