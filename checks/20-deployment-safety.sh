#!/bin/bash
# P-20: Deployment safety
# Pre-deployment checks: debug mode disabled, test credentials removed,
# health endpoints accessible, rollback mechanisms in place.

echo "P-20: Deployment Safety"

SRC="${SOURCE_DIR:-.}"

# Check for debug mode / dev mode in production configs
debug_mode=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.properties" \
  "debug.*true\|devmode.*true\|dev-mode.*true\|trace.*true" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|#\|enabled: false" \
  | head -5)

if [[ -z "$debug_mode" ]]; then
  record "PASS" "P-20 No debug mode" "No debug/dev mode enabled in configs"
else
  count=$(echo "$debug_mode" | wc -l)
  record "WARN" "P-20 No debug mode" "$count debug/dev mode settings found in configs"
fi

# Check for test credentials in production configs
test_creds=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.properties" --include="*.sh" \
  "test.*password\|admin.*admin\|password123\|changeme\|default.*secret" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|example\|template\|#" \
  | head -5)

if [[ -z "$test_creds" ]]; then
  record "PASS" "P-20 No test credentials" "No test/default credentials in configs"
else
  count=$(echo "$test_creds" | wc -l)
  record "FAIL" "P-20 No test credentials" "$count test/default credentials in production configs"
fi

# Check for health endpoint
health=$(grep -rn --include="$SRC_EXT" \
  "$HEALTH_ENDPOINT_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go" \
  | head -3)

if [[ -n "$health" ]]; then
  record "PASS" "P-20 Health endpoint" "Health check endpoint found"
else
  record "WARN" "P-20 Health endpoint" "No health check endpoint found"
fi

# Check for DB migration files (structured deployment)
migrations=$(find "$SRC/db/migrations" -name "*.sql" 2>/dev/null | wc -l)

if [[ $migrations -gt 0 ]]; then
  record "PASS" "P-20 DB migrations" "$migrations migration files (structured deployment)"
else
  record "WARN" "P-20 DB migrations" "No migration files found"
fi
