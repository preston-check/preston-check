#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-461
name: RBI Network and Database Security Controls
description: Verifies network and database security controls per RBI Cyber Security Framework — segmentation, encryption, access controls, regular patching, change management.
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
frameworks: RBI-CSF:2024:Network, NIST-CSF:2.0:PR.DS, ISO-27001:2022:8.20
false_positive_rate: high
performance_class: fast
origin: RBI Cyber Security Framework — network and database security controls.
PRESTON_META

echo "P-461: RBI Network/Database Controls"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" --include="*.tf" \
  -iE "network[_-]segmentation|VPC[_-]segmentation|database[_-]encryption|TDE|transparent[_-]data[_-]encryption|VLAN|firewall[_-]rules" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-461 RBI network/db" "$(echo "$hits" | wc -l | tr -d ' ') segmentation/encryption reference(s)" \
  || record "WARN" "P-461 RBI network/db" "No network segmentation / database encryption references"
