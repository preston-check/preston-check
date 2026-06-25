#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-39
name: Alerting & Monitoring
description: Checks circuit breakers, alert integration.
category: live-monitoring
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:10.7, SOC2:TSC-2017:CC7.3, ISO-27001:2022:8.16, NIST-CSF:2.0:DE.AE-4, CIS-v8:8.11
PRESTON_META


# P-39: Alerting & Anomaly Detection
echo "P-39: Alerting & Monitoring"
SRC="${SOURCE_DIR:-.}"
circuit=$(grep -rn --include="*.java" --include="*.yml" "CircuitBreaker\|@CircuitBreaker\|resilience4j\|@Retryable\|fallback" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$circuit" ]]; then record "PASS" "P-39 Circuit breakers" "Circuit breaker/retry patterns found"; else record "WARN" "P-39 Circuit breakers" "No circuit breaker patterns on external calls"; fi
alerting=$(grep -rn --include="*.java" --include="*.yml" "SNS\|sendAlert\|notify.*admin\|LimitAlertService\|sendEmail.*alert\|sendSMS.*alert" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$alerting" ]]; then record "PASS" "P-39 Alert integration" "Alert notification integration found"; else record "WARN" "P-39 Alert integration" "No alert notification system"; fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "circuitbreaker|gobreaker|resiliency|SNS|sendAlert|notify.*admin|RateLimiter|ratelimit" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-39 Circuit Breaker/Alert (Go)" "Circuit breaker/alert integration found in Go code"
  else
    record "WARN" "P-39 Circuit Breaker/Alert (Go)" "No circuit breaker/alert patterns found in Go code"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "circuit_breaker|retry|SNS|send_alert|notify_admin|governor|ratelimit|RateLimiter" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-39 Circuit Breaker/Alert (Rust)" "Circuit breaker/alert integration found in Rust code"
  else
    record "WARN" "P-39 Circuit Breaker/Alert (Rust)" "No circuit breaker/alert patterns found in Rust code"
  fi
fi
