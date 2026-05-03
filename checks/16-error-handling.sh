#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-16
name: Error Handling
description: Checks for printStackTrace, empty catch blocks, stack trace leaks.
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
frameworks: PCI-DSS:4.0:6.2.4, SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.25, CIS-v8:16.1
PRESTON_META

# P-16: Error handling and graceful degradation
# Financial systems must never expose stack traces, must handle errors
# gracefully, and must not leak internal state on failure.

echo "P-16: Error Handling"

SRC="${SOURCE_DIR:-.}"

# Check for e.printStackTrace() (stack trace leak to logs/stdout)
print_stack=$(grep -rn --include="*.java" \
  "\.printStackTrace()" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" \
  | wc -l)

if [[ $print_stack -eq 0 ]]; then
  record "PASS" "P-16 No printStackTrace" "No e.printStackTrace() calls (use logger instead)"
else
  record "WARN" "P-16 No printStackTrace" "$print_stack e.printStackTrace() calls (should use logger)"
fi

# Check for catch blocks that swallow exceptions silently
empty_catch=$(grep -rn --include="*.java" -A1 \
  "catch.*Exception" \
  "$SRC/Common/src" "$SRC/Payments-logic/src" 2>/dev/null \
  | grep -B1 "^[^}]*}$" \
  | grep "catch" \
  | grep -v "test\|Test\|target\|ignored\|intentional\|swallow\|fire.and.forget" \
  | wc -l)

if [[ $empty_catch -eq 0 ]]; then
  record "PASS" "P-16 No swallowed exceptions" "No empty catch blocks found"
elif [[ $empty_catch -lt 5 ]]; then
  record "WARN" "P-16 No swallowed exceptions" "$empty_catch potentially empty catch blocks"
else
  record "FAIL" "P-16 No swallowed exceptions" "$empty_catch empty catch blocks — errors hidden"
fi

# Check for generic error messages (not leaking internals)
generic_errors=$(grep -rn --include="*.java" \
  "\"Internal error\"\|\"Internal server error\"\|\"An error occurred\"" \
  "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$generic_errors" ]]; then
  record "PASS" "P-16 Generic error messages" "Generic error messages used (not leaking internals)"
else
  record "WARN" "P-16 Generic error messages" "Check that error responses don't leak stack traces"
fi
