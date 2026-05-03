#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-98
name: Currency Safety
description: Detects mixed-currency arithmetic and missing currency tagging on amounts.
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


# P-98: Currency Code Safety & Cross-Currency Arithmetic
# Mixing currencies in arithmetic operations (adding USD to EUR) is a category error.
# Financial systems must enforce currency matching before any calculation.
echo "P-98: Currency Safety"
SRC="${SOURCE_DIR:-.}"

# Check for currency validation before arithmetic
currency_check=$(grep -rn --include="*.java" --include="*.ts" \
  "currency.*match\|same.*currency\|currency.*equals\|currency.*==\|validateCurrency\|currency.*check\|assertCurrency" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$currency_check" ]]; then
  record "PASS" "P-98 Currency matching" "Currency matching validation found before arithmetic"
else
  # Check if there are multi-currency operations at all
  multi_currency=$(grep -rn --include="*.java" "currency\|Currency\|ISO_4217\|currencyCode" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | wc -l | tr -d ' ')
  if [[ "$multi_currency" -gt 10 ]]; then
    record "WARN" "P-98 Currency matching" "Multi-currency system but no currency matching before arithmetic — risk of mixing USD+EUR" "$(echo "$multi_currency" | head -10)"
  else
    record "PASS" "P-98 Currency matching" "Single-currency or minimal currency handling"
  fi
fi

# Check for ISO 4217 currency code usage (not freeform strings)
iso_currency=$(grep -rn --include="*.java" --include="*.ts" \
  "Currency\.getInstance\|ISO_4217\|currencyCode.*[A-Z]\{3\}\|java\.util\.Currency" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$iso_currency" ]]; then
  record "PASS" "P-98 ISO 4217" "ISO 4217 currency code enforcement found"
else
  record "WARN" "P-98 ISO 4217" "No ISO 4217 currency validation — freeform strings risk invalid currency codes" "$(echo "$iso_currency" | head -10)"
fi

# Check for decimal place awareness per currency (JPY has 0, BTC has 8, USD has 2)
decimal_aware=$(grep -rn --include="*.java" --include="*.ts" \
  "decimal.*place\|minor.*unit\|fraction.*digit\|getDefaultFractionDigits\|currency.*scale\|currency.*precision" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$decimal_aware" ]]; then
  record "PASS" "P-98 Decimal awareness" "Currency-specific decimal place handling found"
else
  record "WARN" "P-98 Decimal awareness" "No per-currency decimal place handling — JPY has 0 decimals, BTC has 8, USD has 2" "$(echo "$decimal_aware" | head -10)"
fi
