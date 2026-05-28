#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-04
name: Rate Limiting
description: Checks for missing rate limiting on API endpoints.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.4.1, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.6, OWASP-API:2023:API4, NIST-CSF:2.0:PR.IR-1, CIS-v8:13.3
PRESTON_META


# P-04: Rate limiting on endpoints
# Preston made 21,201 calls to /client/config in rapid succession.
# Every public and authenticated endpoint should have rate limiting.

echo "P-04: Rate Limiting"

SRC="${SOURCE_DIR:-.}"

# Language-aware controller detection
if [[ "$DETECTED_LANG" == "go" ]]; then
  controllers=$(find "$SRC" -name "*handler*.go" -o -name "*controller*.go" -o -name "*routes*.go" 2>/dev/null \
    | grep -v "test\|vendor\|_test\.go" | head -20)
elif [[ "$DETECTED_LANG" == "python" ]]; then
  controllers=$(find "$SRC" -name "*views*.py" -o -name "*routes*.py" -o -name "*endpoints*.py" 2>/dev/null \
    | grep -v "test\|__pycache__\|venv" | head -20)
else
  controllers=$(find "$SRC" -name "*Controller.java" -path "*/src/*" ! -path "*/test/*" ! -path "*/target/*" 2>/dev/null)
fi

total_controllers=0
rate_limited=0

for c in $controllers; do
  ((total_controllers++))
  if grep -q "$RATE_LIMIT_PATTERN" "$c" 2>/dev/null; then
    ((rate_limited++))
  fi
done

if [[ $total_controllers -eq 0 ]]; then
  # Also check for rate limiting in middleware/router setup
  middleware_rl=$(grep -rn --include="$SRC_EXT" "$RATE_LIMIT_PATTERN" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
  if [[ -n "$middleware_rl" ]]; then
    record "PASS" "P-04 Rate limiting" "Rate limiting found in middleware/router"
  else
    record "SKIP" "P-04 Rate limiting" "No controllers found"
  fi
elif [[ $rate_limited -eq $total_controllers ]]; then
  record "PASS" "P-04 Rate limiting" "All $total_controllers controllers have rate limiting"
elif [[ $rate_limited -gt 0 ]]; then
  unprotected=$((total_controllers - rate_limited))
  record "WARN" "P-04 Rate limiting" "$unprotected of $total_controllers controllers lack rate limiting" "$(echo "$middleware_rl" | head -10)"
else
  record "FAIL" "P-04 Rate limiting" "No controllers have rate limiting ($total_controllers found)" "$(echo "$middleware_rl" | head -10)"
fi
