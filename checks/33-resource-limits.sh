#!/bin/bash
# P-33: API Request Size & Timeout Limits — OWASP API #4
echo "P-33: Resource Limits"
SRC="${SOURCE_DIR:-.}"

body_limit=$(grep -rn --include="*.yml" --include="*.yaml" \
  "max-body-size\|maxRequestSize\|max-content-length\|multipart.*max-size\|netty.*maxInitial" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#" | head -3)
if [[ -n "$body_limit" ]]; then
  record "PASS" "P-33 Request body limit" "Request body size limits configured"
else
  record "WARN" "P-33 Request body limit" "No request body size limits found"
fi

timeouts=$(grep -rn --include="$SRC_EXT" --include="*.yml" \
  "$HTTP_TIMEOUT_PATTERN" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -5)
if [[ -n "$timeouts" ]]; then
  record "PASS" "P-33 HTTP timeouts" "Outbound HTTP client timeouts configured"
else
  record "FAIL" "P-33 HTTP timeouts" "No HTTP client timeouts — risk of thread pool exhaustion"
fi

pagination=$(grep -rn --include="$SRC_EXT" \
  "Pageable\|@QueryValue.*page\|@QueryValue.*limit\|LIMIT.*OFFSET\|setMaxResults\|pagination\|PageRequest" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$pagination" ]]; then
  record "PASS" "P-33 Pagination" "Pagination on list endpoints found"
else
  record "WARN" "P-33 Pagination" "No pagination found — unbounded queries risk"
fi
