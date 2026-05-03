#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-19
name: API Versioning
description: Checks for unversioned APIs, deprecated endpoints.
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
frameworks: PCI-DSS:4.0:6.3.1, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, OWASP-API:2023:API9, NIST-CSF:2.0:ID.AM-2, CIS-v8:2.1
PRESTON_META


# P-19: API versioning and deprecation safety
# Public-facing APIs must be versioned to prevent breaking changes.
# Deprecated endpoints must not expose more data than current endpoints.

echo "P-19: API Versioning"

SRC="${SOURCE_DIR:-.}"

# Check for versioned API paths
versioned=$(grep -rn --include="$SRC_EXT" \
  "$API_VERSION_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|dist\|vendor\|_test\.go" \
  | head -10)

if [[ -n "$versioned" ]]; then
  count=$(echo "$versioned" | wc -l)
  record "PASS" "P-19 API versioning" "$count versioned API paths found"
else
  record "WARN" "P-19 API versioning" "No versioned API paths (e.g., /api/v1/) found"
fi

# Check for deprecated/legacy endpoints still active
deprecated=$(grep -rn --include="$SRC_EXT" \
  "@Deprecated\|DEPRECATED\|// TODO.*remove\|// LEGACY\|//nolint.*deprecated" \
  "$SRC" 2>/dev/null \
  | grep -i "controller\|endpoint\|route\|handler" \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -10)

if [[ -z "$deprecated" ]]; then
  record "PASS" "P-19 No deprecated endpoints" "No deprecated/legacy endpoints found"
else
  count=$(echo "$deprecated" | wc -l)
  record "WARN" "P-19 No deprecated endpoints" "$count deprecated endpoints still active"
fi
