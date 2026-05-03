#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-03
name: Information Leakage
description: Detects exception messages, sensitive fields, and internal data in API responses.
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
frameworks: PCI-DSS:4.0:6.2.4.3, SOC2:TSC-2017:CC7.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.12, OWASP-API:2023:API3, NIST-CSF:2.0:PR.DS-2, CIS-v8:3.12
PRESTON_META


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
