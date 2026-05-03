#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-28
name: WAF & DDoS
description: Checks for WAF integration, geo-blocking, OFAC screening.
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
frameworks: PCI-DSS:4.0:6.4.1, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.20, NIST-CSF:2.0:PR.PT-4, CIS-v8:13.6
PRESTON_META


# P-28: WAF Rules & DDoS Protection
echo "P-28: WAF & DDoS"
SRC="${SOURCE_DIR:-.}"

waf=$(grep -rn --include="*.java" \
  "WAF\|waf\|IpSet\|WebACL\|WafIpSet\|GeoMatch" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$waf" ]]; then
  record "PASS" "P-28 WAF integration" "WAF/IP set management found"
else
  record "WARN" "P-28 WAF integration" "No WAF integration found" "$(echo "$waf" | head -10)"
fi

geo=$(grep -rn --include="*.java" --include="*.yml" \
  "country.*block\|geo.*block\|OFAC\|sanctioned\|restricted.*country\|blocked.*jurisdiction" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$geo" ]]; then
  record "PASS" "P-28 Geo-blocking" "Country/jurisdiction screening found"
else
  record "WARN" "P-28 Geo-blocking" "No OFAC/geo-blocking found" "$(echo "$geo" | head -10)"
fi
