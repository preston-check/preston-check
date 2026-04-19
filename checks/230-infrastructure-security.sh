#!/bin/bash
# P-230: Infrastructure Security
echo "P-230: Infrastructure Security"
SRC="${SOURCE_DIR:-.}"

pool_config=$(grep -rn --include="*.yml" --include="*.yaml" --include="$SRC_EXT" 'HikariCP\|hikari\|connectionPool\|maxPoolSize\|maximumPoolSize\|pool.*size' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$pool_config" ]]; then record "PASS" "P-230 Connection pooling" "Database connection pooling configured"; else record "WARN" "P-230 Connection pooling" "No connection pool configuration — risk of connection exhaustion"; fi

shutdown=$(grep -rn --include="$SRC_EXT" 'ShutdownHook\|@PreDestroy\|shutdownGracefully\|Runtime.*addShutdown\|onApplicationEvent.*Shutdown' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$shutdown" ]]; then record "PASS" "P-230 Graceful shutdown" "Graceful shutdown hooks found"; else record "WARN" "P-230 Graceful shutdown" "No shutdown hooks — in-flight transactions may be lost on restart"; fi

health=$(grep -rn --include="*.yml" --include="*.yaml" 'health.*enabled\|health.*sensitive\|/health' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | wc -l | tr -d ' ')
if [[ $health -gt 3 ]]; then record "PASS" "P-230 Health endpoints" "$health health endpoint configs found"; else record "WARN" "P-230 Health endpoints" "Few health endpoints — all services need /health for ALB monitoring"; fi

circuit=$(grep -rn --include="$SRC_EXT" 'CircuitBreaker\|circuit.*breaker\|Resilience4j\|@Retry\|@RateLimiter\|fallback' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$circuit" ]]; then record "PASS" "P-230 Resilience patterns" "Circuit breaker/retry patterns found"; else record "WARN" "P-230 Resilience patterns" "No circuit breaker patterns — cascading failures risk"; fi

dlq=$(grep -rn --include="$SRC_EXT" 'dead.*letter\|DLQ\|retry.*queue\|failed.*queue\|error.*queue\|maxRetries\|retryCount' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$dlq" ]]; then record "PASS" "P-230 Error recovery" "Dead letter queue/retry patterns found"; else record "WARN" "P-230 Error recovery" "No dead letter queue — failed operations may be silently lost"; fi

secret_mgr=$(grep -rn --include="$SRC_EXT" 'SecretsManager\|secretsmanager\|Vault\|KMS\|KeyVault\|ConfigurationManager' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$secret_mgr" ]]; then record "PASS" "P-230 Secret management" "Centralized secret management found"; else record "FAIL" "P-230 Secret management" "No centralized secret management — secrets must not be hardcoded"; fi
