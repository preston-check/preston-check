#!/bin/bash
# P-28: WAF Rules & DDoS Protection
echo "P-28: WAF & DDoS"
SRC="${SOURCE_DIR:-.}"

waf=$(grep -rn --include="*.java" \
  "WAF\|waf\|IpSet\|WebACL\|WafIpSet\|GeoMatch" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$waf" ]]; then
  record "PASS" "P-28 WAF integration" "WAF/IP set management found"
else
  record "WARN" "P-28 WAF integration" "No WAF integration found"
fi

geo=$(grep -rn --include="*.java" --include="*.yml" \
  "country.*block\|geo.*block\|OFAC\|sanctioned\|restricted.*country\|blocked.*jurisdiction" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$geo" ]]; then
  record "PASS" "P-28 Geo-blocking" "Country/jurisdiction screening found"
else
  record "WARN" "P-28 Geo-blocking" "No OFAC/geo-blocking found"
fi
