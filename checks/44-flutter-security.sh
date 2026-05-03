#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-44
name: Flutter/Dart Security
description: Checks hardcoded keys, cert pinning, secure storage.
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
frameworks: PCI-DSS:4.0:3.4, PCI-DSS:4.0:4.2, SOC2:TSC-2017:CC6.7, ISO-27001:2022:8.26
PRESTON_META

# P-44: Flutter/Dart Mobile Security
echo "P-44: Mobile Security (Flutter)"
SRC="${SOURCE_DIR:-.}"
dart_dirs=$(find "$SRC" -maxdepth 3 -name "pubspec.yaml" ! -path "*/target/*" 2>/dev/null)
if [[ -z "$dart_dirs" ]]; then record "SKIP" "P-44 Mobile security" "No Flutter projects found"; return 0 2>/dev/null || exit 0; fi
for pubspec in $dart_dirs; do
  dart_src=$(dirname "$pubspec")/lib
  [[ -d "$dart_src" ]] || continue
  secrets=$(grep -rn --include="*.dart" 'apiKey.*=.*"[a-zA-Z0-9]\{20,\}\|secret.*=.*"[a-zA-Z0-9]\{20,\}' "$dart_src" 2>/dev/null | head -3)
  if [[ -z "$secrets" ]]; then record "PASS" "P-44 No Dart secrets" "No hardcoded secrets in Dart"; else record "FAIL" "P-44 Dart secrets" "Hardcoded secrets in Dart source"; fi
  cert_pin=$(grep -rn --include="*.dart" --include="pubspec.yaml" "certificate.*pin\|SecurityContext\|badCertificateCallback\|ssl_pinning" "$dart_src" "$(dirname $pubspec)" 2>/dev/null | head -3)
  if [[ -n "$cert_pin" ]]; then record "PASS" "P-44 Cert pinning" "Certificate pinning found"; else record "WARN" "P-44 Cert pinning" "No certificate pinning in mobile app"; fi
done
