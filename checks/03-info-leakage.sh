#!/bin/bash
# P-03: Information leakage in API responses
# Preston's session polling returned Vouched keys, full fee structure,
# all permissions, and internal IDs. API responses should minimize data exposure.

echo "P-03: Information Leakage"

SRC="${SOURCE_DIR:-.}"

# Check for exception messages returned to client
exception_leak=$(grep -rn --include="*.java" \
  "e\.getMessage()\|e\.toString()\|e\.getStackTrace()\|e\.printStackTrace()" \
  "$SRC" 2>/dev/null \
  | grep -i "return\|response\|body\|payload\|toJackson\|json" \
  | grep -v "log\.\|LOG\.\|test\|Test\|target\|node_modules" \
  | head -10)

if [[ -z "$exception_leak" ]]; then
  record "PASS" "P-03 Exception leakage" "No exception messages in API responses"
else
  count=$(echo "$exception_leak" | wc -l)
  record "WARN" "P-03 Exception leakage" "$count potential exception message leaks in responses"
fi

# Check for sensitive fields in serialized objects without @JsonIgnore
sensitive_fields=$(grep -rn --include="*.java" \
  "private.*password\|private.*secret\|private.*token\|private.*apiKey\|private.*salt" \
  "$SRC" 2>/dev/null \
  | grep -v "@JsonIgnore\|@JsonProperty.*access.*WRITE\|test\|Test\|target" \
  | grep -v "log\.\|LOG\.\|transient" \
  | head -10)

if [[ -z "$sensitive_fields" ]]; then
  record "PASS" "P-03 Sensitive field exposure" "Sensitive fields properly hidden"
else
  count=$(echo "$sensitive_fields" | wc -l)
  record "WARN" "P-03 Sensitive field exposure" "$count sensitive fields may be serialized (check @JsonIgnore)"
fi
