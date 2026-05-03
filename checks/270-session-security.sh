#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-270
name: Session Security
description: Session Security security check (see COMPLIANCE_MAPPING.md for details).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

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
