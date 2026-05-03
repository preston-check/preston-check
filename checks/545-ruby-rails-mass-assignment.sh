#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-545
name: Ruby on Rails Mass Assignment Protection
description: Detects Rails controllers using params.permit! (allow all) or assigning attributes without strong-parameter filtering. Mass-assignment vulnerabilities let attackers set protected fields via untrusted form data.
category: code-scan
severity: high
languages: ruby
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-API:2023:API6, CWE:915
cwe: 915
false_positive_rate: medium
performance_class: fast
origin: Recurring Rails vulnerability class; strong-parameters introduced in Rails 4 to address it.
PRESTON_META

echo "P-545: Ruby Rails Mass Assignment"

SRC="${SOURCE_DIR:-.}"
rb_count=$(find "$SRC" -name "*.rb" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rb_count" -eq 0 ]] && { record "SKIP" "P-545 Ruby mass assignment" "No Ruby files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.rb" -E "params\.permit!|update_attributes\s*\(\s*params\)|new\s*\(\s*params\s*\)" "$SRC" 2>/dev/null \
  | grep -vE "/spec/|/test/|/vendor/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-545 Ruby mass assignment" "$(echo "$unsafe" | wc -l | tr -d ' ') mass-assignment pattern(s)" "$sample"; } \
  || record "PASS" "P-545 Ruby mass assignment" "No params.permit! or unfiltered update_attributes found"
