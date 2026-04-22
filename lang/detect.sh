#!/bin/bash
###############################################################################
# Language auto-detection for Preston-Check
# Detects the primary language of the source directory and sets
# language-specific variables for file extensions and security patterns.
###############################################################################

detect_language() {
  local src="${1:-.}"

  # Count files by extension
  local java_count=$(find "$src" -name "*.java" -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')
  local go_count=$(find "$src" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
  local py_count=$(find "$src" -name "*.py" -not -path "*/__pycache__/*" -not -path "*/venv/*" 2>/dev/null | wc -l | tr -d ' ')
  local ts_count=$(find "$src" \( -name "*.ts" -o -name "*.tsx" \) -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" 2>/dev/null | wc -l | tr -d ' ')
  local js_count=$(find "$src" \( -name "*.js" -o -name "*.jsx" \) -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" 2>/dev/null | wc -l | tr -d ' ')
  local rs_count=$(find "$src" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')

  # Determine primary language
  local max=$java_count
  DETECTED_LANG="java"

  if [[ $go_count -gt $max ]]; then max=$go_count; DETECTED_LANG="go"; fi
  if [[ $py_count -gt $max ]]; then max=$py_count; DETECTED_LANG="python"; fi
  if [[ $ts_count -gt $max ]]; then max=$ts_count; DETECTED_LANG="typescript"; fi
  if [[ $js_count -gt $max ]]; then max=$js_count; DETECTED_LANG="javascript"; fi
  if [[ $rs_count -gt $max ]]; then max=$rs_count; DETECTED_LANG="rust"; fi

  # Fallback: check for go.mod, pom.xml, package.json, Cargo.toml
  if [[ $max -eq 0 ]]; then
    if [[ -f "$src/tsconfig.json" ]] || find "$src" -name "tsconfig.json" -maxdepth 3 -not -path "*/node_modules/*" 2>/dev/null | grep -q .; then DETECTED_LANG="typescript"
    elif [[ -f "$src/go.mod" ]]; then DETECTED_LANG="go"
    elif [[ -f "$src/pom.xml" ]] || [[ -f "$src/build.gradle" ]]; then DETECTED_LANG="java"
    elif [[ -f "$src/package.json" ]]; then DETECTED_LANG="javascript"
    elif [[ -f "$src/requirements.txt" ]] || [[ -f "$src/pyproject.toml" ]]; then DETECTED_LANG="python"
    elif [[ -f "$src/Cargo.toml" ]]; then DETECTED_LANG="rust"
    fi
  fi

  # Build list of all detected languages for display
  DETECTED_LANGS=""
  [[ $java_count -gt 0 ]] && DETECTED_LANGS="${DETECTED_LANGS}Java($java_count) "
  [[ $ts_count -gt 0 ]] && DETECTED_LANGS="${DETECTED_LANGS}TypeScript($ts_count) "
  [[ $js_count -gt 0 ]] && DETECTED_LANGS="${DETECTED_LANGS}JavaScript($js_count) "
  [[ $py_count -gt 0 ]] && DETECTED_LANGS="${DETECTED_LANGS}Python($py_count) "
  [[ $go_count -gt 0 ]] && DETECTED_LANGS="${DETECTED_LANGS}Go($go_count) "
  [[ $rs_count -gt 0 ]] && DETECTED_LANGS="${DETECTED_LANGS}Rust($rs_count) "
  [[ -z "$DETECTED_LANGS" ]] && DETECTED_LANGS="unknown"

  export DETECTED_LANG
  export DETECTED_LANGS
}

# Load language-specific patterns
load_language_profile() {
  local lang="$1"
  local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  # Source code file extensions for grep --include
  case "$lang" in
    java)
      export SRC_EXT="*.java"
      export SRC_EXTS=("*.java" "*.kt")        # Java + Kotlin
      export CONTROLLER_PATTERN="*Controller.java"
      export SERVICE_PATTERN="*Service.java"
      export CONFIG_EXT="*.yml *.yaml *.properties *.xml"
      # Security patterns
      export AUTH_ANNOTATION="@Secured\|@RolesAllowed\|@PreAuthorize\|isValid()\|validateSession"
      export RATE_LIMIT_PATTERN="RateLimiter\|@RateLimit\|RateLimiterFilter\|rateLimiter"
      export SESSION_IP_PATTERN="login_ip\|loginIp\|session.*ip.*store\|addHash.*ip"
      export SESSION_EXPIRE_PATTERN="session_expires\|expire.*session\|TTL.*session\|setex\|EXPIRE"
      export SESSION_KILL_PATTERN="deleteSessionCache\|killAllSessions\|deleteHashAll.*session\|clearConversation"
      export BLACKLIST_PATTERN="blacklist\|blacklisted\|BLACK_LIST\|isBlacklisted\|HackingDetectionService.checkRegistration\|HackingDetectionService.isBlocked"
      export EXCEPTION_LEAK_PATTERN="getMessage()\|getStackTrace\|\.printStackTrace\|e\.toString()"
      export SENSITIVE_FIELD_PATTERN="password.*json\|creditCard.*json\|ssn.*json\|secret.*json"
      export FLOAT_MONEY_PATTERN="float.*amount\|double.*balance\|float.*price\|double.*fee\|Float.*amount\|Double.*balance"
      export PASSWORD_HASH_PATTERN="PBKDF2\|bcrypt\|scrypt\|argon2\|PasswordEncoder\|MessageDigest.*SHA\|HashPassword\|generateHashPassword"
      export JWT_VERIFY_PATTERN="verify.*jwt\|validateToken\|JWTVerifier\|parseClaimsJws\|Jwts.parser\|micronaut-security-jwt\|JWT_GENERATOR_SIGNATURE_SECRET"
      export WEBHOOK_HANDLER_PATTERN="webhook\|Webhook\|handleCallback"
      export FINANCIAL_MUTATION_PATTERN="funds_out\|withdraw\|transfer\|debit\|payVendor"
      export FOR_UPDATE_PATTERN="FOR UPDATE\|FOR NO KEY UPDATE\|advisory.*lock\|pg_advisory\|ForUpdate\|findPosition.*ForUpdate"
      export SECURE_RANDOM_PATTERN="SecureRandom\|crypto/rand"
      export HTTP_TIMEOUT_PATTERN="Timeout\|timeout\|ReadTimeout\|ConnectTimeout\|setConnectTimeout\|RequestConfig\|setSocketTimeout"
      export NEGATIVE_AMOUNT_PATTERN="amount.*<=.*0\|amount.*<.*0\|isNegative\|signum.*<\|LessThanOrEqual.*Zero"
      export API_VERSION_PATTERN="/api/v[0-9]\|/v[0-9]/\|@Version"
      export HEALTH_ENDPOINT_PATTERN="/health\|HealthCheck\|healthcheck\|liveness\|readiness"
      export ROUNDING_MODE_PATTERN="RoundingMode\|HALF_UP\|HALF_EVEN\|CEILING\|FLOOR\|AssetPrecision\|forDisplay\|forStorage"
      export BIG_DECIMAL_TYPE="BigDecimal"
      ;;
    go)
      export SRC_EXT="*.go"
      export SRC_EXTS=("*.go")
      export CONTROLLER_PATTERN="*handler*.go *controller*.go *routes*.go"
      export SERVICE_PATTERN="*service*.go"
      export CONFIG_EXT="*.yml *.yaml *.toml *.env"
      # Security patterns (Go equivalents)
      export AUTH_ANNOTATION="Authenticate\|RequireAuth\|authMiddleware\|ValidateSession\|jwt.*Validate"
      export RATE_LIMIT_PATTERN="RateLimit\|rateLimiter\|rateLimit\|limiter\|throttle"
      export SESSION_IP_PATTERN="IPAddress\|ip_address\|ClientIP\|RemoteAddr\|GetClientIP"
      export SESSION_EXPIRE_PATTERN="ExpiresAt\|SessionTTL\|session_ttl\|Expiration\|SetEx"
      export SESSION_KILL_PATTERN="BlacklistSession\|RevokeSession\|DeleteSession\|killSession\|RevokeAll"
      export BLACKLIST_PATTERN="blacklist\|Blacklisted\|BLACK_LIST\|IsBlacklisted\|IsBlockedStatus"
      export EXCEPTION_LEAK_PATTERN="err\.Error()\|fmt\.Errorf.*%v.*err\|json.*error.*internal"
      export SENSITIVE_FIELD_PATTERN="password.*json\|Password.*json.*-\|json:\"-\""
      export FLOAT_MONEY_PATTERN="float32.*amount\|float64.*balance\|float.*price\|float.*fee"
      export PASSWORD_HASH_PATTERN="bcrypt\|argon2\|pbkdf2\|PasswordHasher\|HashPassword\|CompareHash"
      export JWT_VERIFY_PATTERN="ValidateAccessToken\|ParseWithClaims\|jwt\.Parse\|VerifyToken\|jwtManager"
      export WEBHOOK_HANDLER_PATTERN="webhook\|Webhook\|HandleCallback\|VerifySignature"
      export FINANCIAL_MUTATION_PATTERN="Withdraw\|withdraw\|Transfer\|Deposit\|PayOut"
      export FOR_UPDATE_PATTERN="FOR UPDATE\|FOR NO KEY UPDATE\|advisory.*lock\|pg_advisory\|Atomically"
      export SECURE_RANDOM_PATTERN="crypto/rand\|rand\.Read\|uuid\.New"
      export HTTP_TIMEOUT_PATTERN="Timeout:\|timeout\|ReadTimeout\|WriteTimeout\|http\.Client.*Timeout"
      export NEGATIVE_AMOUNT_PATTERN="LessThanOrEqual.*Zero\|LessThan.*Zero\|IsNegative\|amount.*<=.*0"
      export API_VERSION_PATTERN="/api/v[0-9]\|/v[0-9]/\|api\.Group"
      export HEALTH_ENDPOINT_PATTERN="/health\|HealthHandler\|healthcheck\|Live\|Ready"
      export ROUNDING_MODE_PATTERN="RoundingMode\|Round\|StringFixed\|Truncate"
      export BIG_DECIMAL_TYPE="decimal\.Decimal\|decimal\.New"
      ;;
    python)
      export SRC_EXT="*.py"
      export SRC_EXTS=("*.py")
      export CONTROLLER_PATTERN="*views*.py *routes*.py *endpoints*.py"
      export SERVICE_PATTERN="*service*.py"
      export CONFIG_EXT="*.yml *.yaml *.toml *.env *.cfg"
      export AUTH_ANNOTATION="login_required\|@authenticated\|@jwt_required\|permission_required"
      export RATE_LIMIT_PATTERN="rate_limit\|RateLimit\|throttle\|Throttle"
      export SESSION_IP_PATTERN="ip_address\|remote_addr\|REMOTE_ADDR\|get_client_ip"
      export SESSION_EXPIRE_PATTERN="expires\|session_ttl\|SESSION_COOKIE_AGE\|max_age"
      export SESSION_KILL_PATTERN="session\.flush\|session\.delete\|logout\|revoke_token"
      export BLACKLIST_PATTERN="blacklist\|is_blacklisted\|blocked_users"
      export EXCEPTION_LEAK_PATTERN="traceback\|str(e)\|repr(e)\|exc_info"
      export SENSITIVE_FIELD_PATTERN="password.*serializer\|exclude.*password"
      export FLOAT_MONEY_PATTERN="float.*amount\|float.*balance\|float.*price"
      export PASSWORD_HASH_PATTERN="bcrypt\|argon2\|pbkdf2\|make_password\|check_password"
      export JWT_VERIFY_PATTERN="jwt\.decode\|verify_token\|validate_token"
      export WEBHOOK_HANDLER_PATTERN="webhook\|handle_webhook\|callback"
      export FINANCIAL_MUTATION_PATTERN="withdraw\|transfer\|deposit\|payout"
      export FOR_UPDATE_PATTERN="select_for_update\|FOR UPDATE\|with_for_update"
      export SECURE_RANDOM_PATTERN="secrets\.\|os\.urandom\|SystemRandom"
      export HTTP_TIMEOUT_PATTERN="timeout=\|Timeout\|connect_timeout"
      export NEGATIVE_AMOUNT_PATTERN="amount.*<=.*0\|amount.*<.*0\|Decimal.*0"
      export API_VERSION_PATTERN="/api/v[0-9]\|/v[0-9]/"
      export HEALTH_ENDPOINT_PATTERN="/health\|healthcheck\|liveness\|readiness"
      export ROUNDING_MODE_PATTERN="ROUND_HALF_UP\|quantize\|Decimal.*round"
      export BIG_DECIMAL_TYPE="Decimal\|decimal\.Decimal"
      ;;
    typescript|javascript)
      export SRC_EXT="*.ts *.tsx *.js *.jsx"
      export SRC_EXTS=("*.ts" "*.tsx" "*.js" "*.jsx")
      export CONTROLLER_PATTERN="*handler*.ts *controller*.ts *routes*.ts *server.ts"
      export SERVICE_PATTERN="*service*.ts *service*.js"
      export CONFIG_EXT="*.yml *.yaml *.json *.env"
      export AUTH_ANNOTATION="authenticate\|requireAuth\|verifyToken\|withMiddleware\|isAuthenticated\|jwt.*verify"
      export RATE_LIMIT_PATTERN="rateLimit\|rateLimiter\|RateLimit\|throttle\|express-rate-limit"
      export SESSION_IP_PATTERN="ip_address\|ipAddress\|req\.ip\|x-forwarded-for\|X-Real-IP"
      export SESSION_EXPIRE_PATTERN="expiresAt\|session.*ttl\|SESSION_TIMEOUT\|maxAge\|cookie.*expires"
      export SESSION_KILL_PATTERN="killAllUserSessions\|revokeSession\|revokeToken\|session\.destroy\|deleteSession\|revoked.*true"
      export BLACKLIST_PATTERN="blacklist\|Blacklist\|isBlocked\|blocked.*check\|checkBlacklist\|GlobalBlacklist"
      export EXCEPTION_LEAK_PATTERN="err\.message\|error\.stack\|catch.*res.*json.*error\|Internal Server Error"
      export SENSITIVE_FIELD_PATTERN="password.*json\|select.*password\|omit.*password\|exclude.*password"
      export FLOAT_MONEY_PATTERN="parseFloat.*amount\|Number.*balance\|toFixed.*fee"
      export PASSWORD_HASH_PATTERN="bcrypt\|argon2\|pbkdf2\|scrypt\|hashPin\|createHash.*sha256"
      export JWT_VERIFY_PATTERN="jwt\.verify\|jsonwebtoken\|verifyToken\|validateToken"
      export WEBHOOK_HANDLER_PATTERN="webhook\|Webhook\|handleCallback\|verifySignature\|verifyTwilioSignature"
      export FINANCIAL_MUTATION_PATTERN="withdraw\|transfer\|send.*money\|createRemittance\|pay_vendor\|executeAction"
      export FOR_UPDATE_PATTERN="FOR UPDATE\|advisory.*lock\|\\\$executeRaw.*UPDATE"
      export SECURE_RANDOM_PATTERN="crypto\.randomBytes\|crypto\.randomUUID\|nanoid\|uuid"
      export HTTP_TIMEOUT_PATTERN="timeout\|Timeout\|AbortController\|signal.*abort"
      export NEGATIVE_AMOUNT_PATTERN="amount.*<=.*0\|amount.*<.*0\|Math\.max.*0"
      export API_VERSION_PATTERN="/api/v[0-9]\|/v[0-9]/"
      export HEALTH_ENDPOINT_PATTERN="/health\|healthcheck\|health.*ok"
      export ROUNDING_MODE_PATTERN="roundMoney\|ROUND_HALF_UP\|toFixed\|Math\.round.*100\|Decimal.*round"
      export BIG_DECIMAL_TYPE="Decimal\|decimal\|BigNumber"
      ;;
    *)
      # Fallback: try all common extensions
      export SRC_EXT="*.java *.go *.py *.ts *.js *.rs"
      export SRC_EXTS=("*.java" "*.go" "*.py" "*.ts" "*.js")
      export CONTROLLER_PATTERN="*Controller* *handler* *routes*"
      export SERVICE_PATTERN="*Service* *service*"
      export CONFIG_EXT="*.yml *.yaml *.toml *.env"
      export AUTH_ANNOTATION="auth\|authenticate\|login_required\|@Secured"
      export RATE_LIMIT_PATTERN="rateLimit\|rate_limit\|throttle"
      export SESSION_IP_PATTERN="ip_address\|loginIp\|ClientIP"
      export SESSION_EXPIRE_PATTERN="expire\|TTL\|session_ttl"
      export SESSION_KILL_PATTERN="deleteSession\|killSession\|revoke"
      export BLACKLIST_PATTERN="blacklist"
      export EXCEPTION_LEAK_PATTERN="getMessage\|err\.Error\|traceback"
      export SENSITIVE_FIELD_PATTERN="password.*json"
      export FLOAT_MONEY_PATTERN="float.*amount\|double.*balance"
      export PASSWORD_HASH_PATTERN="bcrypt\|argon2\|pbkdf2\|scrypt"
      export JWT_VERIFY_PATTERN="jwt.*verify\|validateToken\|parseToken"
      export WEBHOOK_HANDLER_PATTERN="webhook"
      export FINANCIAL_MUTATION_PATTERN="withdraw\|transfer\|deposit"
      export FOR_UPDATE_PATTERN="FOR UPDATE\|advisory.*lock\|Atomically"
      export SECURE_RANDOM_PATTERN="SecureRandom\|crypto/rand\|secrets\."
      export HTTP_TIMEOUT_PATTERN="Timeout\|timeout"
      export NEGATIVE_AMOUNT_PATTERN="amount.*<=.*0\|LessThanOrEqual.*Zero"
      export API_VERSION_PATTERN="/api/v[0-9]\|/v[0-9]/"
      export HEALTH_ENDPOINT_PATTERN="/health\|healthcheck"
      export ROUNDING_MODE_PATTERN="RoundingMode\|ROUND_HALF_UP\|StringFixed"
      export BIG_DECIMAL_TYPE="BigDecimal\|decimal\.Decimal\|Decimal"
      ;;
  esac
}

# Helper: build grep --include flags from SRC_EXT
src_include_flags() {
  local result=""
  for ext in ${SRC_EXT}; do
    result="$result --include=$ext"
  done
  echo "$result"
}

export -f src_include_flags
