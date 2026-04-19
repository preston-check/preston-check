#!/bin/bash
# P-270: Session Security
echo "P-270: Session Security"
SRC="${SOURCE_DIR:-.}"

session_timeout=$(grep -rn --include="$SRC_EXT" --include="*.yml" --include="*.yaml" 'session.*timeout\|session.*expire\|session.*ttl\|idle.*timeout\|maxInactive' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$session_timeout" ]]; then record "PASS" "P-270 Session timeout" "Session timeout/expiration configured"; else record "WARN" "P-270 Session timeout" "No session timeout — stale sessions remain active indefinitely"; fi

concurrent=$(grep -rn --include="$SRC_EXT" 'concurrent.*session\|session.*limit\|max.*session\|single.*session\|invalidate.*previous\|SessionSentinel' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$concurrent" ]]; then record "PASS" "P-270 Concurrent sessions" "Concurrent session management found"; else record "WARN" "P-270 Concurrent sessions" "No concurrent session limits — account takeover harder to detect"; fi

session_regen=$(grep -rn --include="$SRC_EXT" 'regenerate.*session\|newSession\|invalidate.*session.*new\|session.*fixation' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$session_regen" ]]; then record "PASS" "P-270 Session fixation" "Session regeneration after auth found"; else record "WARN" "P-270 Session fixation" "No session regeneration after login — session fixation risk"; fi

lockout=$(grep -rn --include="$SRC_EXT" 'lockout\|lock.*out\|failed.*attempts\|login.*attempts\|progressive.*lock\|getLockoutMinutes' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$lockout" ]]; then record "PASS" "P-270 Account lockout" "Account lockout on failed attempts found"; else record "FAIL" "P-270 Account lockout" "No account lockout — brute force attacks unchecked"; fi
