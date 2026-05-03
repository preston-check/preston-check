#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-39
name: Alerting & Monitoring
description: Checks circuit breakers, alert integration.
category: live-monitoring
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:10.7, SOC2:TSC-2017:CC7.3, ISO-27001:2022:8.16, NIST-CSF:2.0:DE.AE-4, CIS-v8:8.11
PRESTON_META


# P-39: Alerting & Anomaly Detection
echo "P-39: Alerting & Monitoring"
SRC="${SOURCE_DIR:-.}"
circuit=$(grep -rn --include="*.java" --include="*.yml" "CircuitBreaker\|@CircuitBreaker\|resilience4j\|@Retryable\|fallback" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$circuit" ]]; then record "PASS" "P-39 Circuit breakers" "Circuit breaker/retry patterns found"; else record "WARN" "P-39 Circuit breakers" "No circuit breaker patterns on external calls"; fi
alerting=$(grep -rn --include="*.java" --include="*.yml" "SNS\|sendAlert\|notify.*admin\|LimitAlertService\|sendEmail.*alert\|sendSMS.*alert" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$alerting" ]]; then record "PASS" "P-39 Alert integration" "Alert notification integration found"; else record "WARN" "P-39 Alert integration" "No alert notification system"; fi
