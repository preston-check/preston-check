#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-547
name: Ruby Hardcoded Secrets
description: Detects hardcoded API keys, secrets, and tokens in Ruby source. Rails credentials should live in encrypted credentials files, not source code.
category: code-scan
severity: critical
languages: ruby
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.6.2, NIST-CSF:2.0:PR.DS-1, CWE:798
cwe: 798
false_positive_rate: medium
performance_class: fast
origin: Common Ruby/Rails security finding; Rails offers `rails credentials:edit` for encrypted-at-rest secrets.
PRESTON_META

echo "P-547: Ruby Hardcoded Secrets"

SRC="${SOURCE_DIR:-.}"
rb_count=$(find "$SRC" -name "*.rb" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rb_count" -eq 0 ]] && { record "SKIP" "P-547 Ruby secrets" "No Ruby files found"; return 0 2>/dev/null || true; }

hits=$(grep -rn --include="*.rb" -E "(api_key|secret_key|password)\s*=\s*[\"'][a-zA-Z0-9_+/=]{16,}[\"']" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/spec/|/test/|/vendor/|ENV\[|Rails.application.credentials" || true)
[[ -n "$hits" ]] && { sample=$(echo "$hits" | head -10); record "FAIL" "P-547 Ruby secrets" "$(echo "$hits" | wc -l | tr -d ' ') hardcoded credential(s)" "$sample"; } \
  || record "PASS" "P-547 Ruby secrets" "No hardcoded secrets in Ruby source"
