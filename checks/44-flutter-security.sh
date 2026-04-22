#!/bin/bash
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
