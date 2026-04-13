#!/bin/bash
# P-66: Dormant Account Reactivation Monitoring
# Accounts that go dormant then suddenly become active with large transactions
# are a classic money laundering indicator. Financial systems MUST flag this.
echo "P-66: Dormant Account Monitoring"
SRC="${SOURCE_DIR:-.}"

# Check for dormant/inactive account detection
dormant=$(grep -rn --include="*.java" --include="*.ts" \
  "dormant\|inactive.*account\|last.*login\|last.*activity\|days.*since\|reactivat\|account.*age\|stale.*account" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$dormant" ]]; then
  record "PASS" "P-66 Dormant detection" "Dormant/inactive account monitoring found"
else
  record "WARN" "P-66 Dormant detection" "No dormant account reactivation monitoring — flag accounts resuming activity after prolonged inactivity"
fi

# Check for step-up authentication on reactivation
stepup=$(grep -rn --include="*.java" --include="*.ts" \
  "step.*up.*auth\|re.*verify\|additional.*verification\|enhanced.*due.*diligence\|edd\|re.*kyc" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$stepup" ]]; then
  record "PASS" "P-66 Step-up auth" "Enhanced verification patterns found"
else
  record "WARN" "P-66 Step-up auth" "No step-up authentication for high-risk activities (reactivation, large tx, new destination)"
fi

# Check for login anomaly detection
login_anomaly=$(grep -rn --include="*.java" --include="*.ts" \
  "unusual.*login\|new.*device\|new.*ip\|geo.*anomal\|impossible.*travel\|login.*alert" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$login_anomaly" ]]; then
  record "PASS" "P-66 Login anomaly" "Login anomaly detection found"
else
  record "WARN" "P-66 Login anomaly" "No login anomaly detection (new device/IP/geolocation changes)"
fi
