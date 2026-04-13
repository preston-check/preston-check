#!/bin/bash
# P-06: Session security
# Preston exploited sessions with no IP binding and no 2FA requirement.
# Sessions should store login IP and validate it on subsequent requests.

echo "P-06: Session Security"

SRC="${SOURCE_DIR:-.}"

# Check if session stores login IP
session_ip=$(grep -rn --include="*.java" \
  "login_ip\|loginIp\|session.*ip.*store\|addHash.*ip" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" \
  | head -5)

if [[ -n "$session_ip" ]]; then
  record "PASS" "P-06 Session IP binding" "Session stores login IP for comparison"
else
  record "WARN" "P-06 Session IP binding" "No evidence of login IP stored in session"
fi

# Check session expiration
session_ttl=$(grep -rn --include="*.java" \
  "session_expires\|expire.*session\|TTL.*session\|setex\|EXPIRE" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" \
  | head -3)

if [[ -n "$session_ttl" ]]; then
  record "PASS" "P-06 Session expiration" "Sessions have TTL configured"
else
  record "WARN" "P-06 Session expiration" "No session expiration found"
fi

# Check for session kill on sensitive operations
session_kill=$(grep -rn --include="*.java" \
  "deleteSessionCache\|killAllSessions\|deleteHashAll.*session\|clearConversation" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$session_kill" ]]; then
  record "PASS" "P-06 Session kill capability" "Session termination available for remediation"
else
  record "FAIL" "P-06 Session kill capability" "No session kill mechanism found"
fi
