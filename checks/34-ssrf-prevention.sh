#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-34
name: SSRF Prevention
description: Checks user-supplied URLs in HTTP clients, metadata endpoint blocking.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.2.4, ISO-27001:2022:8.26, OWASP-API:2023:API7:2023, CIS-v8:13.4
PRESTON_META

# P-34: SSRF Prevention — OWASP API #7
echo "P-34: SSRF Prevention"
SRC="${SOURCE_DIR:-.}"

user_url=$(grep -rn --include="*.java" \
  "callbackUrl\|callback_url\|webhookUrl\|webhook_url\|redirectUrl\|notificationUrl" \
  "$SRC" 2>/dev/null | grep -i "httpClient\|restTemplate\|webClient\|fetch\|request\|URL\|URI" \
  | grep -v "test\|Test\|target" | head -5)
if [[ -z "$user_url" ]]; then
  record "PASS" "P-34 No user URLs to HTTP" "No user-supplied URLs passed to HTTP clients"
else
  count=$(echo "$user_url" | wc -l)
  record "WARN" "P-34 User URLs to HTTP" "$count potential SSRF vectors — user URLs in HTTP client calls"
fi

metadata=$(grep -rn --include="*.java" \
  "169.254.169.254\|metadata.*block\|validateUrl.*internal\|isInternalUrl\|SSRF" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$metadata" ]]; then
  record "PASS" "P-34 Metadata protection" "AWS metadata endpoint protection found"
else
  record "WARN" "P-34 Metadata protection" "No explicit metadata endpoint (169.254.169.254) blocking"
fi
