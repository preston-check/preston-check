#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-43
name: Container Security
description: Checks for root containers, secrets in images.
category: infra-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:2.2, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.8, CIS-v8:4.6
PRESTON_META

# P-43: Container & Runtime Security
echo "P-43: Container Security"
SRC="${SOURCE_DIR:-.}"
dockerfiles=$(find "$SRC" -maxdepth 4 -name "Dockerfile*" ! -path "*/target/*" 2>/dev/null)
if [[ -z "$dockerfiles" ]]; then record "SKIP" "P-43 Container security" "No Dockerfiles found"; return 0 2>/dev/null || exit 0; fi
for df in $dockerfiles; do
  dir=$(basename "$(dirname "$df")")
  if ! grep -q "^USER" "$df" 2>/dev/null; then record "WARN" "P-43 Root container $dir" "No USER directive — runs as root"; fi
  if grep -q "COPY.*\.env\|COPY.*\.key\|COPY.*\.pem\|COPY.*secret" "$df" 2>/dev/null; then record "FAIL" "P-43 Secrets in image $dir" "Dockerfile copies secrets into image"; fi
done
