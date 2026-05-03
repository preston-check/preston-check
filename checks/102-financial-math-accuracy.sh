#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-102
name: Financial Math Accuracy
description: Detects division without scale, premature truncation, unsafe rounding modes.
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
frameworks: PCI-DSS:4.0:6.2.4, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.28, NIST-CSF:2.0:PR.DS-6
PRESTON_META


###############################################################################
# P-102: Financial Math Accuracy
#
# Checks for patterns that introduce mathematical discrepancies in financial
# calculations: inconsistent rounding, intermediate precision loss, silent
# truncation, accumulation drift, and comparison errors.
#
# The "penny problem": a 0.001 rounding error on 1M transactions = $1,000 lost.
# These bugs are invisible in testing and only surface at scale.
###############################################################################
echo "P-102: Financial Math Accuracy"
SRC="${SOURCE_DIR:-$1}"
SRC="${SRC:-.}"

# ─── CHECK 1: Inconsistent rounding across codebase ─────────────────
# Using HALF_UP in one place and HALF_EVEN in another creates penny
# differences that compound over time.

if [[ "$DETECTED_LANG" == "java" ]]; then
  modes=$(grep -rn --include="*.java" -oP 'RoundingMode\.\w+' "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target" | awk -F: '{print $NF}' | sort | uniq -c | sort -rn)
  mode_count=$(echo "$modes" | sed '/^$/d' | wc -l | tr -d ' ')
  if [[ $mode_count -gt 2 ]]; then
    record "FAIL" "P-102 Rounding consistency" "$mode_count different RoundingModes — pick one (HALF_UP for banking, HALF_EVEN for statistics) and use it everywhere"
    echo "$modes" | head -5 | while read line; do echo "    $line"; done
  elif [[ $mode_count -ge 1 ]]; then
    primary=$(echo "$modes" | head -1 | awk '{print $2}')
    record "PASS" "P-102 Rounding consistency" "Consistent rounding: $primary"
  else
    record "WARN" "P-102 Rounding consistency" "No RoundingMode found — financial calculations must specify rounding explicitly"
  fi
elif [[ "$DETECTED_LANG" == "go" ]]; then
  modes=$(grep -rn --include="*.go" -oE 'Round(HalfUp|HalfEven|Up|Down|Ceil|Floor|Banker)' "$SRC" 2>/dev/null \
    | grep -v "test\|vendor\|_test\.go" | awk -F: '{print $NF}' | sort | uniq -c | sort -rn)
  mode_count=$(echo "$modes" | sed '/^$/d' | wc -l | tr -d ' ')
  if [[ $mode_count -gt 2 ]]; then
    record "FAIL" "P-102 Rounding consistency" "$mode_count different rounding strategies — standardize across codebase"
  elif [[ $mode_count -ge 1 ]]; then
    record "PASS" "P-102 Rounding consistency" "Consistent rounding strategy found"
  else
    record "WARN" "P-102 Rounding consistency" "No explicit rounding strategy found"
  fi
elif [[ "$DETECTED_LANG" == "python" ]]; then
  modes=$(grep -rn --include="*.py" -oE 'ROUND_(HALF_UP|HALF_EVEN|HALF_DOWN|UP|DOWN|CEILING|FLOOR|05UP)' "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|__pycache__\|venv" | awk -F: '{print $NF}' | sort | uniq -c | sort -rn)
  mode_count=$(echo "$modes" | sed '/^$/d' | wc -l | tr -d ' ')
  if [[ $mode_count -gt 2 ]]; then
    record "FAIL" "P-102 Rounding consistency" "$mode_count different rounding modes"
  elif [[ $mode_count -ge 1 ]]; then
    record "PASS" "P-102 Rounding consistency" "Consistent rounding found"
  else
    record "WARN" "P-102 Rounding consistency" "No explicit rounding context — use decimal.getcontext().rounding"
  fi
else
  record "WARN" "P-102 Rounding consistency" "Check rounding consistency manually for $DETECTED_LANG"
fi

# ─── CHECK 2: Intermediate precision loss ────────────────────────────
# Chained operations like a.multiply(b).divide(c) can lose precision
# if intermediate results aren't scaled properly. The fix is to use
# higher intermediate scale than the final result.

if [[ "$DETECTED_LANG" == "java" ]]; then
  # Pattern: .multiply(...).divide(...) without MathContext
  chain_ops=$(grep -rn --include="*.java" \
    -E '\.multiply\(.*\)\.divide\(|\.divide\(.*\)\.multiply\(' \
    "$SRC" 2>/dev/null \
    | grep -v "MathContext\|test\|Test\|target\|//\|/\*" | head -5)
  if [[ -z "$chain_ops" ]]; then
    record "PASS" "P-102 Intermediate precision" "No unguarded chained multiply/divide — intermediate precision preserved"
  else
    count=$(echo "$chain_ops" | wc -l | tr -d ' ')
    record "WARN" "P-102 Intermediate precision" "$count chained multiply().divide() without MathContext — may lose intermediate precision"
  fi
fi

# ─── CHECK 3: Casting between numeric types ──────────────────────────
# Casting BigDecimal to double/float, or long to int, silently loses
# precision or overflows.

if [[ "$DETECTED_LANG" == "java" ]]; then
  unsafe_cast=$(grep -rn --include="*.java" \
    -E '\.doubleValue\(\)|\.floatValue\(\)|\.longValue\(\)|\.intValue\(\)' \
    "$SRC" 2>/dev/null \
    | grep -iE "amount|balance|price|fee|cost|total|payment|rate|tax|discount|spread|commission" \
    | grep -v "test\|Test\|target\|//\|/\*\|Formatting\|format\|display\|template\|Variable\|setVariable\|log\.\|toString\|String\.format" | head -10)
  if [[ -z "$unsafe_cast" ]]; then
    record "PASS" "P-102 Numeric casting" "No doubleValue()/floatValue() on financial BigDecimals"
  else
    count=$(echo "$unsafe_cast" | wc -l | tr -d ' ')
    record "FAIL" "P-102 Numeric casting" "$count BigDecimal.doubleValue()/floatValue() calls on money — precision loss"
    echo "$unsafe_cast" | head -3 | while read line; do echo "    $line"; done
  fi
elif [[ "$DETECTED_LANG" == "go" ]]; then
  unsafe_cast=$(grep -rn --include="*.go" \
    -E 'float64\(.*amount|float64\(.*balance|float64\(.*price|float32\(' \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|vendor\|_test\.go\|//\|/\*" | head -10)
  if [[ -z "$unsafe_cast" ]]; then
    record "PASS" "P-102 Numeric casting" "No float64() casts on financial values"
  else
    count=$(echo "$unsafe_cast" | wc -l | tr -d ' ')
    record "WARN" "P-102 Numeric casting" "$count float64() casts on financial values — use Decimal type"
  fi
fi

# ─── CHECK 4: String-to-number parsing without scale ─────────────────
# new BigDecimal("0.1") is exact. new BigDecimal(0.1) is NOT.
# Double.parseDouble("0.1") → 0.1000000000000000055511...

if [[ "$DETECTED_LANG" == "java" ]]; then
  # new BigDecimal(double) — the classic bug
  bd_from_double=$(grep -rn --include="*.java" \
    -E 'new BigDecimal\([^"]*[0-9]+\.[0-9]' \
    "$SRC" 2>/dev/null \
    | grep -v 'new BigDecimal\("' \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)
  if [[ -z "$bd_from_double" ]]; then
    record "PASS" "P-102 BigDecimal construction" "No new BigDecimal(double) — uses BigDecimal(String) for exact values"
  else
    count=$(echo "$bd_from_double" | wc -l | tr -d ' ')
    record "FAIL" "P-102 BigDecimal construction" "$count new BigDecimal(double) — use new BigDecimal(\"value\") for exact representation"
    echo "$bd_from_double" | head -3 | while read line; do echo "    $line"; done
  fi

  # parseDouble/parseFloat used for money parsing
  parse_float=$(grep -rn --include="*.java" \
    -E '(Double|Float)\.(parseDouble|parseFloat|valueOf)\(' \
    "$SRC" 2>/dev/null \
    | grep -iE "amount|balance|price|fee|cost|total|payment" \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)
  if [[ -z "$parse_float" ]]; then
    record "PASS" "P-102 Money parsing" "No Double.parseDouble() for financial parsing — uses BigDecimal"
  else
    count=$(echo "$parse_float" | wc -l | tr -d ' ')
    record "WARN" "P-102 Money parsing" "$count Double.parseDouble() on financial values — use new BigDecimal(string)"
  fi
fi

# ─── CHECK 5: Accumulation drift (summing in a loop) ────────────────
# Summing 10,000 BigDecimals of $0.10 should be exactly $1,000.00.
# But summing doubles: sum += 0.1 → 999.9999999999986
# Also: stream().reduce() on BigDecimal must use BigDecimal.ZERO as identity.

if [[ "$DETECTED_LANG" == "java" ]]; then
  # Check for += on double/float with money-related names
  accum_float=$(grep -rn --include="*.java" \
    -E '(total|sum|running|accum|balance)\s*\+=\s*' \
    "$SRC" 2>/dev/null \
    | grep -v 'BigDecimal\|\.add(\|Count\|count\|test\|Test\|target\|//\|/\*\|String\|int \|long ' | head -5)
  if [[ -z "$accum_float" ]]; then
    record "PASS" "P-102 Accumulation safety" "No float/double accumulation on financial totals"
  else
    count=$(echo "$accum_float" | wc -l | tr -d ' ')
    record "WARN" "P-102 Accumulation safety" "$count += accumulations on financial vars — verify using BigDecimal.add(), not double +="
  fi
fi

# ─── CHECK 6: Percentage/rate calculations ───────────────────────────
# fee = amount * 0.029 is wrong (double literal).
# fee = amount.multiply(new BigDecimal("0.029")) is correct.

if [[ "$DETECTED_LANG" == "java" ]]; then
  rate_literal=$(grep -rn --include="*.java" \
    -E '\*\s*0\.[0-9]+[^"f]|\*\s*[0-9]+\.[0-9]+[^"f]' \
    "$SRC" 2>/dev/null \
    | grep -iE "fee|rate|percent|tax|discount|commission|spread|margin" \
    | grep -v "BigDecimal\|test\|Test\|target\|//\|/\*" | head -5)
  if [[ -z "$rate_literal" ]]; then
    record "PASS" "P-102 Rate calculations" "No double literals in rate/fee calculations"
  else
    count=$(echo "$rate_literal" | wc -l | tr -d ' ')
    record "WARN" "P-102 Rate calculations" "$count rate calculations using double literals — use BigDecimal(\"0.029\") not 0.029"
  fi
fi

# ─── CHECK 7: Scale inconsistency in database vs code ────────────────
# DB column is NUMERIC(19,2) but code uses scale 8 → truncation on save.
# Or vice versa: DB allows 8 decimals but display rounds to 2.

db_scales=$(grep -rn --include="*.sql" \
  -iE 'NUMERIC|DECIMAL' \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|--" \
  | grep -oE '[0-9]+,\s*[0-9]+' | awk -F, '{print $2}' | sort | uniq -c | sort -rn)
scale_count=$(echo "$db_scales" | sed '/^$/d' | wc -l | tr -d ' ')

if [[ $scale_count -gt 2 ]]; then
  record "WARN" "P-102 Scale consistency" "$scale_count different NUMERIC scales in DB — inconsistent decimal places cause truncation on transfer between tables"
  echo "$db_scales" | head -3 | while read line; do echo "    scale($line)"; done
elif [[ $scale_count -ge 1 ]]; then
  primary_scale=$(echo "$db_scales" | head -1 | awk '{print $2}')
  record "PASS" "P-102 Scale consistency" "Consistent DB decimal scale: $primary_scale"
else
  record "WARN" "P-102 Scale consistency" "No NUMERIC/DECIMAL columns found — verify money columns use precise types"
fi

# ─── CHECK 8: Equality comparison on decimals ────────────────────────
# BigDecimal.equals() considers scale: new BigDecimal("1.0").equals(new BigDecimal("1.00")) is FALSE.
# Must use compareTo() == 0 for value equality.

if [[ "$DETECTED_LANG" == "java" ]]; then
  bd_equals=$(grep -rn --include="*.java" \
    -E '\.equals\(' \
    "$SRC" 2>/dev/null \
    | grep -iE "BigDecimal\|amount\|balance\|price\|fee\|total" \
    | grep -v "test\|Test\|target\|String\|null\|//\|/\*\|compareTo" | head -5)
  if [[ -z "$bd_equals" ]]; then
    record "PASS" "P-102 Decimal equality" "No BigDecimal.equals() — uses compareTo() for value comparison"
  else
    count=$(echo "$bd_equals" | wc -l | tr -d ' ')
    record "WARN" "P-102 Decimal equality" "$count .equals() on BigDecimal — use .compareTo() == 0 (equals considers scale: 1.0 != 1.00)"
  fi
fi
