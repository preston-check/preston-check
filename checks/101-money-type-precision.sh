#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-101
name: Money Type Precision
description: Money Type Precision security check (see COMPLIANCE_MAPPING.md for details).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

###############################################################################
# P-101: Money Type Precision
#
# Financial values stored in float/double lose precision due to IEEE 754
# binary representation. $0.10 cannot be represented exactly in float64.
# This check finds every variable declaration, function parameter, return
# type, database column, and DTO field where money/amounts/balances/fees
# use a lossy type instead of a precise one.
#
# Safe types by language:
#   Java:       BigDecimal
#   Go:         shopspring/decimal.Decimal, int64 (cents)
#   Python:     decimal.Decimal
#   TypeScript: string (serialized), Decimal.js, big.js
#   Rust:       rust_decimal::Decimal, i64 (cents)
#   SQL:        NUMERIC, DECIMAL — never FLOAT, DOUBLE, REAL
#
# Named after the classic "$0.1 + $0.2 != $0.3" bug that has caused
# millions in reconciliation losses across fintech history.
###############################################################################
echo "P-101: Money Type Precision"
SRC="${SOURCE_DIR:-$1}"
SRC="${SRC:-.}"

# ─── CHECK 1: Float/double declarations on money fields ─────────────
# These are the most dangerous: a variable holding money in float loses
# precision on every arithmetic operation.

if [[ "$DETECTED_LANG" == "java" ]]; then
  # Java: float/double on money-related variable names
  unsafe_decl=$(grep -rn --include="*.java" \
    -E "(float|double|Float|Double)\s+(amount|balance|price|fee|cost|total|subtotal|tax|discount|rate|spread|margin|revenue|income|payout|refund|credit|debit|deposit|withdrawal|settlement|commission|premium|interest|principal|payment|salary|wage|bonus|tip|cashback|rebate|surcharge)" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|vendor\|//.*float\|/\*\|totalPages\|totalCount\|pageSize\|Math\.ceil\|pagination\|Formatting\|template\|display\|format\|toString" | head -20)

  # Also catch: double getAmount(), float calculateFee(), etc.
  unsafe_return=$(grep -rn --include="*.java" \
    -E "(float|double)\s+(get|calculate|compute|sum|total)(Amount|Balance|Price|Fee|Cost|Total|Tax|Discount|Rate|Payment|Interest|Commission)" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|vendor\|//\|/\*" | head -10)

  # Catch Map<String, Double> or List<Double> holding money
  unsafe_generic=$(grep -rn --include="*.java" \
    -E "(Map|List|Set)<.*,?\s*(Float|Double)\s*>.*((a|A)mount|(b|B)alance|(p|P)rice|(f|F)ee|(c|C)ost|(t|T)otal|(p|P)ayment)" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|vendor\|//\|/\*" | head -10)

elif [[ "$DETECTED_LANG" == "go" ]]; then
  unsafe_decl=$(grep -rn --include="*.go" \
    -E "float(32|64)\s" \
    "$SRC" 2>/dev/null \
    | grep -iE "amount|balance|price|fee|cost|total|payment|rate|spread|commission|deposit|withdrawal|settlement" \
    | grep -v "test\|Test\|vendor\|_test\.go\|//\|/\*" | head -20)
  unsafe_return=""
  unsafe_generic=""

elif [[ "$DETECTED_LANG" == "python" ]]; then
  unsafe_decl=$(grep -rn --include="*.py" \
    -E "(amount|balance|price|fee|cost|total|payment|rate|deposit|settlement)\s*[:=]\s*float\(" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|__pycache__\|venv\|#" | head -20)

  # Also: float type hints on money params
  unsafe_return=$(grep -rn --include="*.py" \
    -E "(amount|balance|price|fee|cost|total|payment):\s*float" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|__pycache__\|venv\|#" | head -10)
  unsafe_generic=""

elif [[ "$DETECTED_LANG" == "typescript" ]] || [[ "$DETECTED_LANG" == "javascript" ]]; then
  # In JS/TS, number is always float64. Check for number type on money fields.
  unsafe_decl=$(grep -rn --include="*.ts" --include="*.tsx" --include="*.js" \
    -E "(amount|balance|price|fee|cost|total|payment|rate|deposit|settlement):\s*number" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|node_modules\|dist\|build\|//\|/\*" | head -20)
  unsafe_return=""
  unsafe_generic=""

elif [[ "$DETECTED_LANG" == "rust" ]]; then
  unsafe_decl=$(grep -rn --include="*.rs" \
    -E "(f32|f64)\s" \
    "$SRC" 2>/dev/null \
    | grep -iE "amount|balance|price|fee|cost|total|payment|rate|deposit|settlement" \
    | grep -v "test\|Test\|target\|//\|/\*" | head -20)
  unsafe_return=""
  unsafe_generic=""

else
  # Fallback: check common float patterns across all languages
  unsafe_decl=$(grep -rn --include="*.java" --include="*.go" --include="*.py" --include="*.ts" --include="*.rs" \
    -iE "(float|double|f32|f64).*(amount|balance|price|fee|cost|total|payment)" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|vendor\|node_modules\|//\|/\*" | head -20)
  unsafe_return=""
  unsafe_generic=""
fi

all_unsafe=""
[[ -n "$unsafe_decl" ]] && all_unsafe+="$unsafe_decl"$'\n'
[[ -n "$unsafe_return" ]] && all_unsafe+="$unsafe_return"$'\n'
[[ -n "$unsafe_generic" ]] && all_unsafe+="$unsafe_generic"$'\n'
all_unsafe=$(echo "$all_unsafe" | sed '/^$/d')

if [[ -z "$all_unsafe" ]]; then
  record "PASS" "P-101 Money type precision" "No float/double used for financial values — all money uses precise types"
else
  count=$(echo "$all_unsafe" | wc -l | tr -d ' ')
  record "FAIL" "P-101 Money type precision" "$count float/double declarations on money fields — use BigDecimal/Decimal instead"
  echo "$all_unsafe" | head -5 | while read line; do
    echo "    $line"
  done
fi

# ─── CHECK 2: Database columns using FLOAT/DOUBLE/REAL for money ────
unsafe_sql=$(grep -rn --include="*.sql" \
  -iE "(FLOAT|DOUBLE|REAL|DOUBLE PRECISION)\s" \
  "$SRC" 2>/dev/null \
  | grep -iE "amount|balance|price|fee|cost|total|payment|rate|deposit|settlement|column|CREATE|ALTER" \
  | grep -v "test\|Test\|target\|node_modules\|vendor\|--" | head -10)

if [[ -z "$unsafe_sql" ]]; then
  record "PASS" "P-101 DB money columns" "No FLOAT/DOUBLE/REAL on financial database columns — uses NUMERIC/DECIMAL"
else
  count=$(echo "$unsafe_sql" | wc -l | tr -d ' ')
  record "FAIL" "P-101 DB money columns" "$count FLOAT/DOUBLE/REAL columns for money — use NUMERIC(precision,scale) or DECIMAL"
  echo "$unsafe_sql" | head -3 | while read line; do
    echo "    $line"
  done
fi

# ─── CHECK 3: JSON serialization losing precision ───────────────────
# When BigDecimal is serialized to JSON as a number, JavaScript's
# Number.parseFloat() truncates it. Safe: serialize as string.

if [[ "$DETECTED_LANG" == "java" ]]; then
  json_number=$(grep -rn --include="*.java" \
    -E "@JsonFormat.*shape.*NUMBER|@JsonSerialize.*NumberSerializer" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)

  if [[ -z "$json_number" ]]; then
    record "PASS" "P-101 JSON precision" "No @JsonFormat NUMBER_FLOAT on BigDecimal — safe serialization"
  else
    count=$(echo "$json_number" | wc -l | tr -d ' ')
    record "WARN" "P-101 JSON precision" "$count BigDecimal fields serialize as JSON number — JavaScript loses precision above 2^53"
  fi
fi

# ─── CHECK 4: Arithmetic on money without BigDecimal ────────────────
# Catching patterns like: amount * rate, price + tax using primitives

if [[ "$DETECTED_LANG" == "java" ]]; then
  primitive_arith=$(grep -rn --include="*.java" \
    -E "(amount|balance|price|fee|total|cost)\s*[\+\-\*\/]=?\s*(amount|balance|price|fee|total|cost|rate|tax|discount)" \
    "$SRC" 2>/dev/null \
    | grep -v "BigDecimal\|\.add\|\.subtract\|\.multiply\|\.divide\|compareTo\|test\|Test\|target\|//\|/\*\|String" | head -10)

  if [[ -z "$primitive_arith" ]]; then
    record "PASS" "P-101 Safe arithmetic" "No primitive arithmetic on money variables — uses BigDecimal methods"
  else
    count=$(echo "$primitive_arith" | wc -l | tr -d ' ')
    record "WARN" "P-101 Safe arithmetic" "$count primitive +/-/* on money variables — use BigDecimal.add()/subtract()/multiply()"
  fi
fi

# ─── CHECK 5: Cents-based integer safety ────────────────────────────
# If using int/long cents representation, verify multiply/divide
# doesn't silently truncate

if [[ "$DETECTED_LANG" == "go" ]]; then
  cents_trunc=$(grep -rn --include="*.go" \
    -E "int64.*\/\s*100|int.*\/\s*100|cents.*\/|amount.*\/.*100" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|vendor\|_test\.go\|//\|/\*" | head -5)

  if [[ -n "$cents_trunc" ]]; then
    count=$(echo "$cents_trunc" | wc -l | tr -d ' ')
    record "WARN" "P-101 Cents truncation" "$count integer division on cents — verify no silent truncation (use math.Round or explicit remainder handling)"
  else
    record "PASS" "P-101 Cents truncation" "No unguarded cents division found"
  fi
fi
