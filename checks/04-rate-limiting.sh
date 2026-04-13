#!/bin/bash
# P-04: Rate limiting on endpoints
# Preston made 21,201 calls to /client/config in rapid succession.
# Every public and authenticated endpoint should have rate limiting.

echo "P-04: Rate Limiting"

SRC="${SOURCE_DIR:-.}"

# Check for @RateLimiter or Resilience4j annotations on controllers
controllers=$(find "$SRC" -name "*Controller.java" -path "*/src/*" ! -path "*/test/*" ! -path "*/target/*" 2>/dev/null)
total_controllers=0
rate_limited=0

for c in $controllers; do
  ((total_controllers++))
  if grep -q "RateLimiter\|@RateLimit\|RateLimiterFilter\|rateLimiter" "$c" 2>/dev/null; then
    ((rate_limited++))
  fi
done

if [[ $total_controllers -eq 0 ]]; then
  record "SKIP" "P-04 Rate limiting" "No controllers found"
elif [[ $rate_limited -eq $total_controllers ]]; then
  record "PASS" "P-04 Rate limiting" "All $total_controllers controllers have rate limiting"
elif [[ $rate_limited -gt 0 ]]; then
  unprotected=$((total_controllers - rate_limited))
  record "WARN" "P-04 Rate limiting" "$unprotected of $total_controllers controllers lack rate limiting"
else
  record "FAIL" "P-04 Rate limiting" "No controllers have rate limiting ($total_controllers found)"
fi
