#!/bin/bash
# P-39: Alerting & Anomaly Detection
echo "P-39: Alerting & Monitoring"
SRC="${SOURCE_DIR:-.}"
circuit=$(grep -rn --include="*.java" --include="*.yml" --max-count=5 "CircuitBreaker\|@CircuitBreaker\|resilience4j\|@Retryable\|fallback" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$circuit" ]]; then record "PASS" "P-39 Circuit breakers" "Circuit breaker/retry patterns found"; else record "WARN" "P-39 Circuit breakers" "No circuit breaker patterns on external calls"; fi
alerting=$(grep -rn --include="*.java" --include="*.yml" --max-count=5 "SNS\|sendAlert\|notify.*admin\|LimitAlertService\|sendEmail.*alert\|sendSMS.*alert" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$alerting" ]]; then record "PASS" "P-39 Alert integration" "Alert notification integration found"; else record "WARN" "P-39 Alert integration" "No alert notification system"; fi
