#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-424
name: OWASP Mobile M5 — Insecure Communication
description: Detects insecure network communication on mobile — cleartext HTTP, missing certificate pinning, missing Network Security Config, allowsArbitraryLoads on iOS ATS.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-MAS:2024:M5, OWASP-MASVS:2.0:NETWORK-1
false_positive_rate: medium
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M5 — Insecure Communication.
PRESTON_META

echo "P-424: Mobile Insecure Communication"

SRC="${SOURCE_DIR:-.}"
cleartext=$(grep -rln --include="*.xml" --include="*.plist" --include="*.kt" --include="*.swift" --include="*.java" --include="*.dart" \
  -iE "cleartextTrafficPermitted\s*=\s*[\"']?true|NSAllowsArbitraryLoads\s*=\s*true|usesCleartextTraffic" "$SRC" 2>/dev/null | grep -v node_modules || true)
pinning=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.xml" \
  -iE "CertificatePinner|pinCertificates|TrustKit|certificate[_-]pinning|pinnedCertificates|network_security_config" "$SRC" 2>/dev/null | grep -v node_modules || true)
if [[ -n "$cleartext" ]]; then
  record "FAIL" "P-424 mobile comm" "$(echo "$cleartext" | wc -l | tr -d ' ') cleartext-traffic configuration(s) detected"
elif [[ -n "$pinning" ]]; then
  record "PASS" "P-424 mobile comm" "$(echo "$pinning" | wc -l | tr -d ' ') certificate-pinning reference(s)"
else
  record "SKIP" "P-424 mobile comm" "No mobile network configuration detected"
fi
