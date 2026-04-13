#!/bin/bash
# P-82: Continuous Defense Model Readiness
# Validates the infrastructure for continuous security monitoring, automatic response,
# and self-healing patterns. Defense must be active 24/7, not just at deploy time.
echo "P-82: Continuous Defense"
SRC="${SOURCE_DIR:-.}"

# Check for real-time security monitoring
realtime=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "security.*monitor\|intrusion.*detect\|anomaly.*detect\|threat.*detect\|real.*time.*alert\|security.*event" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$realtime" ]]; then
  record "PASS" "P-82 Real-time monitoring" "Security monitoring patterns found"
else
  record "WARN" "P-82 Real-time monitoring" "No real-time security monitoring — defense must be active 24/7"
fi

# Check for automatic blocking/quarantine
auto_block=$(grep -rn --include="*.java" --include="*.ts" \
  "auto.*block\|auto.*ban\|quarantine\|blacklist.*auto\|auto.*blacklist\|auto.*suspend\|lock.*account.*auto" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$auto_block" ]]; then
  record "PASS" "P-82 Auto-response" "Automatic blocking/quarantine patterns found"
else
  record "WARN" "P-82 Auto-response" "No automatic threat response — system should auto-block suspicious activity"
fi

# Check for security audit cycle automation
audit_cycle=$(grep -rn --include="*.java" --include="*.ts" --include="*.sh" --include="*.yml" \
  "security.*audit.*cycle\|security.*scan.*schedule\|cron.*security\|scheduled.*audit\|preston.*check\|security.*cron" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$audit_cycle" ]]; then
  record "PASS" "P-82 Audit automation" "Automated security audit cycle found"
else
  record "WARN" "P-82 Audit automation" "No automated security audit scheduling — should run security checks on every deployment"
fi

# Check for circuit breaker patterns
circuit_breaker=$(grep -rn --include="*.java" --include="*.ts" \
  "circuit.*breaker\|CircuitBreaker\|@CircuitBreaker\|breaker.*open\|fallback.*method\|retry.*policy\|bulkhead" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$circuit_breaker" ]]; then
  record "PASS" "P-82 Circuit breakers" "Circuit breaker patterns found"
else
  record "WARN" "P-82 Circuit breakers" "No circuit breaker patterns — cascading failures can take down the entire platform"
fi

# Check for self-healing patterns
self_heal=$(grep -rn --include="*.java" --include="*.ts" --include="*.sh" \
  "self.*heal\|auto.*recover\|auto.*restart\|watchdog\|health.*check.*restart\|zombie.*clean\|cleanup.*cron\|sentinel" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$self_heal" ]]; then
  record "PASS" "P-82 Self-healing" "Self-healing/auto-recovery patterns found"
else
  record "WARN" "P-82 Self-healing" "No self-healing patterns — system should auto-recover from transient failures"
fi

# Check for defense-in-depth (multiple layers)
defense_layers=0
[[ -n $(grep -rl "firewall\|waf\|WAF" "$SRC" 2>/dev/null | head -1) ]] && defense_layers=$((defense_layers + 1))
[[ -n $(grep -rl "@Secured\|authenticate\|JWT\|jwt" "$SRC" 2>/dev/null | head -1) ]] && defense_layers=$((defense_layers + 1))
[[ -n $(grep -rl "encrypt\|AES\|RSA\|cipher" "$SRC" 2>/dev/null | head -1) ]] && defense_layers=$((defense_layers + 1))
[[ -n $(grep -rl "audit\|log.*security\|security.*log" "$SRC" 2>/dev/null | head -1) ]] && defense_layers=$((defense_layers + 1))
[[ -n $(grep -rl "blacklist\|whitelist\|allowlist\|blocklist" "$SRC" 2>/dev/null | head -1) ]] && defense_layers=$((defense_layers + 1))
if [[ $defense_layers -ge 4 ]]; then
  record "PASS" "P-82 Defense in depth" "$defense_layers/5 defense layers active (WAF, auth, encryption, audit, access control)"
elif [[ $defense_layers -ge 2 ]]; then
  record "WARN" "P-82 Defense in depth" "Only $defense_layers/5 defense layers — need WAF, auth, encryption, audit, and access control"
else
  record "FAIL" "P-82 Defense in depth" "Only $defense_layers/5 defense layers active — insufficient defense in depth"
fi
