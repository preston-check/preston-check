#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-553
name: PHP XML External Entity (XXE) Vulnerability
description: Detects XML parsing in PHP without disabling external entity loading (libxml_disable_entity_loader, LIBXML_NOENT). Default PHP libxml configuration is vulnerable to XXE on user-supplied XML.
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
origin: PHP XXE has driven multiple major data-exfiltration incidents; SimpleXMLElement and DOMDocument default to entity expansion in older configurations.
PRESTON_META

echo "P-553: PHP XXE"

SRC="${SOURCE_DIR:-.}"
php_count=$(find "$SRC" -name "*.php" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$php_count" -eq 0 ]] && { record "SKIP" "P-553 PHP XXE" "No PHP files found"; return 0 2>/dev/null || true; }

xml_use=$(grep -rln --include="*.php" -E "SimpleXMLElement|DOMDocument|simplexml_load|loadXML" "$SRC" 2>/dev/null | grep -vE "/test/|/vendor/" || true)
disabled=$(grep -rln --include="*.php" -E "libxml_disable_entity_loader|LIBXML_NOENT|LIBXML_DTDLOAD" "$SRC" 2>/dev/null | grep -vE "/test/|/vendor/" || true)
[[ -z "$xml_use" ]] && { record "SKIP" "P-553 PHP XXE" "No XML parsing detected"; return 0 2>/dev/null || true; }
[[ -n "$disabled" ]] && record "PASS" "P-553 PHP XXE" "$(echo "$disabled" | wc -l | tr -d ' ') file(s) disable external entity loading" \
  || record "WARN" "P-553 PHP XXE" "XML parsing detected without observable XXE protection" "$(echo "$xml_use" | head -10)"
