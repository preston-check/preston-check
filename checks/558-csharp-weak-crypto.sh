#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-558
name: C# / .NET Weak Cryptography
description: Detects use of MD5, SHA1, DES, TripleDES, RC2, or RNGCryptoServiceProvider with weak parameters. Modern .NET code should use SHA-256+, AES, and System.Security.Cryptography.RandomNumberGenerator.
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
frameworks: PCI-DSS:4.0:3.6, NIST-CSF:2.0:PR.DS, CWE:327
cwe: 327
false_positive_rate: low
performance_class: fast
origin: .NET legacy crypto APIs (MD5, SHA1, DES, TripleDES) persist in older code; deprecated in current Microsoft guidance.
PRESTON_META

echo "P-558: C# Weak Cryptography"

SRC="${SOURCE_DIR:-.}"
cs_count=$(find "$SRC" -name "*.cs" -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$cs_count" -eq 0 ]] && { record "SKIP" "P-558 C# weak crypto" "No C# files found"; return 0 2>/dev/null || true; }

weak=$(grep -rn --include="*.cs" -E "MD5(CryptoServiceProvider)?\.|SHA1(CryptoServiceProvider)?\.|DES(CryptoServiceProvider)?\.|TripleDES|RC2CryptoServiceProvider|System\.Random\(" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/Tests/|/bin/|/obj/" || true)
[[ -n "$weak" ]] && { sample=$(echo "$weak" | head -10); record "FAIL" "P-558 C# weak crypto" "$(echo "$weak" | wc -l | tr -d ' ') weak/legacy crypto reference(s)" "$sample"; } \
  || record "PASS" "P-558 C# weak crypto" "No MD5/SHA1/DES/3DES/RC2 references detected"
