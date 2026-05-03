#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-69
name: Exchange Rate Safety
description: Detects stale rates, missing rate bounds, spread limit violations, rate locking.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6
PRESTON_META


# P-69: Currency Conversion & Exchange Rate Safety
# Stale rates, unbounded spreads, and missing rate bounds enable arbitrage and theft.
# Critical for any platform handling multi-currency transactions.
echo "P-69: Exchange Rate Safety"
SRC="${SOURCE_DIR:-.}"

# Check for stale rate protection
stale_rate=$(grep -rn --include="*.java" --include="*.ts" \
  "stale.*rate\|rate.*age\|rate.*expir\|rate.*ttl\|rate.*timeout\|hasPriceFeed\|last.*price.*time\|rate.*fresh" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$stale_rate" ]]; then
  record "PASS" "P-69 Stale rate protection" "Stale exchange rate protection found"
else
  rate_usage=$(grep -rn --include="*.java" "rate\|exchange\|convert\|swap" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | wc -l | tr -d ' ')
  if [[ "$rate_usage" -gt 10 ]]; then
    record "WARN" "P-69 Stale rate protection" "Exchange rate usage found but no staleness check — rates served without freshness validation"
  else
    record "SKIP" "P-69 Stale rate protection" "No significant exchange rate usage found"
  fi
fi

# Check for rate bounds/sanity checks
rate_bounds=$(grep -rn --include="*.java" --include="*.ts" \
  "rate.*bound\|rate.*limit\|rate.*sanity\|max.*rate\|min.*rate\|rate.*reasonable\|rate.*deviation\|rate.*threshold" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|rateLimit" | head -3)
if [[ -n "$rate_bounds" ]]; then
  record "PASS" "P-69 Rate bounds" "Exchange rate sanity bounds found"
else
  record "WARN" "P-69 Rate bounds" "No rate deviation/sanity bounds — a manipulated rate feed could drain accounts"
fi

# Check for spread limits
spread_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "max.*spread\|spread.*limit\|spread.*bound\|spread.*cap\|spread.*check" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$spread_limit" ]]; then
  record "PASS" "P-69 Spread limits" "Spread bounds found"
else
  spread_usage=$(grep -rn --include="*.java" "spread\|markup" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | wc -l | tr -d ' ')
  if [[ "$spread_usage" -gt 3 ]]; then
    record "WARN" "P-69 Spread limits" "Spread calculations exist but no upper bound — a misconfigured spread could overcharge"
  else
    record "PASS" "P-69 Spread limits" "No spread patterns requiring bounds"
  fi
fi

# Check for rate locking (customer quoted rate vs execution rate)
rate_lock=$(grep -rn --include="*.java" --include="*.ts" \
  "lock.*rate\|quoted.*rate\|rate.*lock\|guaranteed.*rate\|rate.*valid\|rate.*window\|rate.*expir" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$rate_lock" ]]; then
  record "PASS" "P-69 Rate locking" "Rate locking/guarantee mechanism found"
else
  record "WARN" "P-69 Rate locking" "No rate locking — customer may see different rate at execution than at quote"
fi
