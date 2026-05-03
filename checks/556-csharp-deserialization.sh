#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-556
name: C# / .NET Insecure Deserialization
description: Detects use of BinaryFormatter, NetDataContractSerializer, SoapFormatter, or unsafe Newtonsoft.Json TypeNameHandling.All. Microsoft has officially deprecated BinaryFormatter due to RCE vulnerability.
category: code-scan
severity: critical
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A08, CWE:502
cwe: 502
false_positive_rate: low
performance_class: fast
origin: BinaryFormatter / TypeNameHandling.All RCE has driven multiple major .NET incidents; Microsoft deprecated BinaryFormatter in .NET 5+.
PRESTON_META

echo "P-556: C# Insecure Deserialization"

SRC="${SOURCE_DIR:-.}"
cs_count=$(find "$SRC" -name "*.cs" -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$cs_count" -eq 0 ]] && { record "SKIP" "P-556 C# deserialization" "No C# files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.cs" -E "BinaryFormatter|NetDataContractSerializer|SoapFormatter|TypeNameHandling\s*=\s*TypeNameHandling\.All|TypeNameHandling\.Auto" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/Tests/|/bin/|/obj/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-556 C# deserialization" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe deserializer reference(s)" "$sample"; } \
  || record "PASS" "P-556 C# deserialization" "No BinaryFormatter / TypeNameHandling.All detected"
