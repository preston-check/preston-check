#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-33
name: Resource Limits
description: Checks request body size, HTTP timeouts, pagination.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: SOC2:TSC-2017:A1.2, ISO-27001:2022:8.6, OWASP-API:2023:API4, NIST-CSF:2.0:PR.DS-4, CIS-v8:13.4
PRESTON_META


# P-33: API Request Size & Timeout Limits — OWASP API #4
echo "P-33: Resource Limits"
SRC="${SOURCE_DIR:-.}"

body_limit=$(grep -rn --include="*.yml" --include="*.yaml" \
  "max-body-size\|maxRequestSize\|max-content-length\|multipart.*max-size\|netty.*maxInitial" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#" | head -3)
if [[ -n "$body_limit" ]]; then
  record "PASS" "P-33 Request body limit" "Request body size limits configured"
else
  record "WARN" "P-33 Request body limit" "No request body size limits found" "$(echo "$body_limit" | head -10)"
fi

timeouts=$(grep -rn --include="$SRC_EXT" --include="*.yml" \
  "$HTTP_TIMEOUT_PATTERN" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -5)
if [[ -n "$timeouts" ]]; then
  record "PASS" "P-33 HTTP timeouts" "Outbound HTTP client timeouts configured"
else
  record "FAIL" "P-33 HTTP timeouts" "No HTTP client timeouts — risk of thread pool exhaustion" "$(echo "$timeouts" | head -10)"
fi

pagination=$(grep -rn --include="$SRC_EXT" \
  "Pageable\|@QueryValue.*page\|@QueryValue.*limit\|LIMIT.*OFFSET\|setMaxResults\|pagination\|PageRequest" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$pagination" ]]; then
  record "PASS" "P-33 Pagination" "Pagination on list endpoints found"
else
  record "WARN" "P-33 Pagination" "No pagination found — unbounded queries risk" "$(echo "$pagination" | head -10)"
fi
