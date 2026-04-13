#!/bin/bash
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
    record "WARN" "P-98 Currency matching" "Multi-currency system but no currency matching before arithmetic — risk of mixing USD+EUR"
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
  record "WARN" "P-98 ISO 4217" "No ISO 4217 currency validation — freeform strings risk invalid currency codes"
fi

# Check for decimal place awareness per currency (JPY has 0, BTC has 8, USD has 2)
decimal_aware=$(grep -rn --include="*.java" --include="*.ts" \
  "decimal.*place\|minor.*unit\|fraction.*digit\|getDefaultFractionDigits\|currency.*scale\|currency.*precision" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$decimal_aware" ]]; then
  record "PASS" "P-98 Decimal awareness" "Currency-specific decimal place handling found"
else
  record "WARN" "P-98 Decimal awareness" "No per-currency decimal place handling — JPY has 0 decimals, BTC has 8, USD has 2"
fi
