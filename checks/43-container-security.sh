#!/bin/bash
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
