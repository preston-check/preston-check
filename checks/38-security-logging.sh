#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-38
name: Security Logging
description: Checks login/transaction/admin action logging completeness.
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
frameworks: PCI-DSS:4.0:10.2, PCI-DSS:4.0:10.3, SOC2:TSC-2017:CC7.1, SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.15, ISO-27001:2022:8.16, NIST-CSF:2.0:DE.CM-1, CIS-v8:8.2
PRESTON_META


# P-38: Security Event Logging Completeness
echo "P-38: Security Logging"
SRC="${SOURCE_DIR:-.}"
login_log=$(grep -rn --include="$SRC_EXT" 'log\..*login\|log\..*signin\|log\..*authenticate\|log\..*CREDENTIALS\|log\..*Login\|log\..*SignIn\|SecurityAuditLogger.logLogin\|security_audit_log' --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$login_log" ]]; then record "PASS" "P-38 Login logging" "Login event logging found"; else record "FAIL" "P-38 Login logging" "No login event logging"; fi
txn_log=$(grep -rn --include="$SRC_EXT" 'log\..*withdraw\|log\..*deposit\|log\..*transfer\|log\..*payment\|log\..*Withdraw\|log\..*Transfer\|SecurityAuditLogger.logTransaction' --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$txn_log" ]]; then record "PASS" "P-38 Transaction logging" "Financial transaction logging found"; else record "FAIL" "P-38 Transaction logging" "No financial transaction logging"; fi
admin_log=$(grep -rn --include="$SRC_EXT" 'log\..*role\|log\..*blacklist\|log\..*approve\|log\..*reject\|audit\|log\..*Blacklist\|log\..*Approve' --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$admin_log" ]]; then record "PASS" "P-38 Admin action logging" "Admin action logging found"; else record "WARN" "P-38 Admin action logging" "No admin action logging"; fi
