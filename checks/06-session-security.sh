#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-06
name: Session Security
description: Checks for IP binding, TTL, session kill mechanisms.
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
frameworks: PCI-DSS:4.0:8.2.8, SOC2:TSC-2017:CC6.1, SOC2:TSC-2017:CC6.3, ISO-27001:2022:8.5, OWASP-API:2023:API2, NIST-CSF:2.0:PR.AA-5, CIS-v8:6.5
PRESTON_META


# P-06: Session security
# Preston exploited sessions with no IP binding and no 2FA requirement.
# Sessions should store login IP and validate it on subsequent requests.

echo "P-06: Session Security"

SRC="${SOURCE_DIR:-.}"

# Check if session stores login IP
session_ip=$(grep -rn --include="$SRC_EXT" \
  "$SESSION_IP_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go\|node_modules" \
  | head -5)

if [[ -n "$session_ip" ]]; then
  record "PASS" "P-06 Session IP binding" "Session stores login IP for comparison"
else
  record "WARN" "P-06 Session IP binding" "No evidence of login IP stored in session" "$(echo "$session_ip" | head -10)"
fi

# Check session expiration
session_ttl=$(grep -rn --include="$SRC_EXT" \
  "$SESSION_EXPIRE_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go\|node_modules" \
  | head -3)

if [[ -n "$session_ttl" ]]; then
  record "PASS" "P-06 Session expiration" "Sessions have TTL configured"
else
  record "WARN" "P-06 Session expiration" "No session expiration found" "$(echo "$session_ttl" | head -10)"
fi

# Check for session kill on sensitive operations
session_kill=$(grep -rn --include="$SRC_EXT" \
  "$SESSION_KILL_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -5)

if [[ -n "$session_kill" ]]; then
  record "PASS" "P-06 Session kill capability" "Session termination available for remediation"
else
  record "FAIL" "P-06 Session kill capability" "No session kill mechanism found" "$(echo "$session_kill" | head -10)"
fi
