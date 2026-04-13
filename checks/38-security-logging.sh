#!/bin/bash
# P-38: Security Event Logging Completeness
echo "P-38: Security Logging"
SRC="${SOURCE_DIR:-.}"
login_log=$(grep -rn --include="*.java" --max-count=5 'log\..*login\|log\..*signin\|log\..*authenticate\|log\..*CREDENTIALS' "$SRC/Registration" "$SRC/Common" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$login_log" ]]; then record "PASS" "P-38 Login logging" "Login event logging found"; else record "FAIL" "P-38 Login logging" "No login event logging"; fi
txn_log=$(grep -rn --include="*.java" --max-count=5 'log\..*withdraw\|log\..*deposit\|log\..*transfer\|log\..*payment' "$SRC/Payments-logic" "$SRC/FireblocksSecureWalletWithdraw-logic" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$txn_log" ]]; then record "PASS" "P-38 Transaction logging" "Financial transaction logging found"; else record "FAIL" "P-38 Transaction logging" "No financial transaction logging"; fi
admin_log=$(grep -rn --include="*.java" --max-count=5 'log\..*role\|log\..*blacklist\|log\..*approve\|log\..*reject\|audit' "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$admin_log" ]]; then record "PASS" "P-38 Admin action logging" "Admin action logging found"; else record "WARN" "P-38 Admin action logging" "No admin action logging"; fi
