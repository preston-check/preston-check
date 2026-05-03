#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-52
name: Timing Attacks
description: Checks constant-time comparison for secrets, .equals() on passwords.
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
frameworks: PCI-DSS:4.0:3.6.1, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-1
PRESTON_META


# P-52: Timing Attack Prevention
# Password comparison, HMAC verification, token comparison must be constant-time.
echo "P-52: Timing Attacks"
SRC="${SOURCE_DIR:-.}"
constant_time=$(grep -rn --include="*.java" \
  "MessageDigest.isEqual\|constantTimeEquals\|timingSafeEqual\|SecureCompare\|slowEquals" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$constant_time" ]]; then
  record "PASS" "P-52 Constant-time compare" "Constant-time comparison for secrets found"
else
  record "WARN" "P-52 Constant-time compare" "No constant-time comparison — timing oracle risk on auth" "$(echo "$constant_time" | head -10)"
fi

string_equals_secret=$(grep -rn --include="*.java" \
  '\.equals.*password\|\.equals.*secret\|\.equals.*token\|\.equals.*signature\|\.equals.*hmac' \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|MessageDigest\|constantTime\|//\|enum\|Enum\|name()" | head -5)
if [[ -z "$string_equals_secret" ]]; then
  record "PASS" "P-52 No .equals() for secrets" "Secrets not compared with .equals()"
else
  count=$(echo "$string_equals_secret" | wc -l)
  record "WARN" "P-52 .equals() for secrets" "$count potential timing-vulnerable secret comparisons" "$(echo "$string_equals_secret" | head -10)"
fi
