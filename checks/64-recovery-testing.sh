#!/bin/bash
# P-64: Recovery Testing Evidence — SOC 2 A1.3, ISO 27001 A.8.14, NIST RC.RP
# Checks for DR test documentation, RTO/RPO definitions, recovery runbooks.
echo "P-64: Recovery Testing"
SRC="${SOURCE_DIR:-.}"

# Check for recovery/DR documentation
recovery_docs=$(find "$SRC" -maxdepth 4 \( \
  -iname "*recovery*" -o -iname "*disaster*" -o -iname "*backup*plan*" \
  -o -iname "*runbook*" -o -iname "*playbook*" -o -iname "*failover*" \
  \) -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -5)
if [[ -n "$recovery_docs" ]]; then
  count=$(echo "$recovery_docs" | wc -l | tr -d ' ')
  record "PASS" "P-64 Recovery documentation" "$count recovery/DR documents found"
else
  record "WARN" "P-64 Recovery documentation" "No disaster recovery or runbook documentation found"
fi

# Check for backup configuration
backup_config=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" --include="*.yaml" --include="*.sh" \
  "backup\|pg_dump\|mysqldump\|snapshot\|rds.*snapshot\|s3.*backup" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$backup_config" ]]; then
  record "PASS" "P-64 Backup configuration" "Database backup references found"
else
  record "WARN" "P-64 Backup configuration" "No database backup configuration references found"
fi

# Check for health check endpoints (needed for failover)
health_check=$(grep -rn --include="*.java" --include="*.ts" \
  "/health\|/readiness\|/liveness\|healthCheck\|health_check" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$health_check" ]]; then
  record "PASS" "P-64 Health endpoints" "Health check endpoints found (supports failover)"
else
  record "WARN" "P-64 Health endpoints" "No health/readiness endpoints found"
fi
