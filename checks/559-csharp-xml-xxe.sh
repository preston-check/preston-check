#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-559
name: C# / .NET XML External Entity (XXE)
description: Detects XmlDocument, XmlReader, or XPathDocument usage without DtdProcessing.Prohibit / XmlResolver=null. .NET XML parsers require explicit hardening to defeat XXE.
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
frameworks: OWASP-Top-10:2021:A05, CWE:611
cwe: 611
false_positive_rate: medium
performance_class: fast
origin: .NET XML XXE remains exploitable when DtdProcessing is enabled; Microsoft documentation explicitly warns about insecure defaults in older Framework versions.
PRESTON_META

echo "P-559: C# XML XXE"

SRC="${SOURCE_DIR:-.}"
cs_count=$(find "$SRC" -name "*.cs" -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$cs_count" -eq 0 ]] && { record "SKIP" "P-559 C# XXE" "No C# files found"; return 0 2>/dev/null || true; }

xml_use=$(grep -rln --include="*.cs" -E "XmlDocument|XmlReader|XPathDocument" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/test/|/Tests/|/bin/|/obj/" || true)
hardened=$(grep -rln --include="*.cs" -E "DtdProcessing\.Prohibit|DtdProcessing\.Ignore|XmlResolver\s*=\s*null" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/test/|/Tests/|/bin/|/obj/" || true)
[[ -z "$xml_use" ]] && { record "SKIP" "P-559 C# XXE" "No XML parsing detected"; return 0 2>/dev/null || true; }
[[ -n "$hardened" ]] && record "PASS" "P-559 C# XXE" "$(echo "$hardened" | wc -l | tr -d ' ') file(s) reference DTD-prohibition / null resolver" \
  || record "WARN" "P-559 C# XXE" "XML parsing detected without observable XXE hardening" "$(echo "$xml_use" | head -10)"
