#!/bin/bash
# P-19: API versioning and deprecation safety
# Public-facing APIs must be versioned to prevent breaking changes.
# Deprecated endpoints must not expose more data than current endpoints.

echo "P-19: API Versioning"

SRC="${SOURCE_DIR:-.}"

# Check for versioned API paths
versioned=$(grep -rn --include="*.java" --include="*.ts" \
  --max-count=10 '"/v[0-9]\|/api/v[0-9]\|@RequestMapping.*v[0-9]' \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|dist" \
  | head -10)

if [[ -n "$versioned" ]]; then
  count=$(echo "$versioned" | wc -l)
  record "PASS" "P-19 API versioning" "$count versioned API paths found"
else
  record "WARN" "P-19 API versioning" "No versioned API paths (e.g., /api/v1/) found"
fi

# Check for deprecated/legacy endpoints still active
deprecated=$(grep -rn --include="*.java" \
  --max-count=10 "@Deprecated\|DEPRECATED\|// TODO.*remove\|// LEGACY" \
  "$SRC" 2>/dev/null \
  | grep -i "controller\|endpoint\|route" \
  | grep -v "test\|Test\|target" \
  | head -10)

if [[ -z "$deprecated" ]]; then
  record "PASS" "P-19 No deprecated endpoints" "No deprecated/legacy endpoints found"
else
  count=$(echo "$deprecated" | wc -l)
  record "WARN" "P-19 No deprecated endpoints" "$count deprecated endpoints still active"
fi
