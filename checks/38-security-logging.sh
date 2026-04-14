#!/bin/bash
# P-38: Security Event Logging Completeness
echo "P-38: Security Logging"
SRC="${SOURCE_DIR:-.}"
login_log=$(grep -rn --include="$SRC_EXT" --max-count=5 'log\..*login\|log\..*signin\|log\..*authenticate\|log\..*CREDENTIALS\|log\..*Login\|log\..*SignIn' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$login_log" ]]; then record "PASS" "P-38 Login logging" "Login event logging found"; else record "FAIL" "P-38 Login logging" "No login event logging"; fi
txn_log=$(grep -rn --include="$SRC_EXT" --max-count=5 'log\..*withdraw\|log\..*deposit\|log\..*transfer\|log\..*payment\|log\..*Withdraw\|log\..*Transfer' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$txn_log" ]]; then record "PASS" "P-38 Transaction logging" "Financial transaction logging found"; else record "FAIL" "P-38 Transaction logging" "No financial transaction logging"; fi
admin_log=$(grep -rn --include="$SRC_EXT" --max-count=5 'log\..*role\|log\..*blacklist\|log\..*approve\|log\..*reject\|audit\|log\..*Blacklist\|log\..*Approve' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$admin_log" ]]; then record "PASS" "P-38 Admin action logging" "Admin action logging found"; else record "WARN" "P-38 Admin action logging" "No admin action logging"; fi
