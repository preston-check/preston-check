#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-28
name: WAF & DDoS
description: Checks for WAF integration, geo-blocking, OFAC screening.
category: infra-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "WAF|waf|IpSet|WebACL|WafIpSet|GeoMatch|country.*block|geo.*block|OFAC|sanctioned" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-28 WAF/DDoS protection (Go)" "WAF/DDoS protection patterns found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "WARN" "P-28 WAF/DDoS protection (Go)" "No WAF/DDoS protection patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "waf|ip_set|WebACL|GeoMatch|country_block|geo_block|OFAC|sanctioned" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-28 WAF/DDoS protection (Rust)" "WAF/DDoS protection patterns found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "WARN" "P-28 WAF/DDoS protection (Rust)" "No WAF/DDoS protection patterns found in Rust files"
  fi
fi
