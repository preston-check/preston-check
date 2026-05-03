#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-548
name: Ruby Insecure Deserialization
description: Detects YAML.load and Marshal.load on untrusted input — both allow arbitrary code execution via crafted payloads. Use YAML.safe_load for YAML, never Marshal.load on external data.
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
frameworks: OWASP-Top-10:2021:A08, CWE:502
cwe: 502
false_positive_rate: medium
performance_class: fast
origin: Recurring Ruby RCE class — YAML.load (insecure default in older Ruby) and Marshal.load are documented attack surfaces.
PRESTON_META

echo "P-548: Ruby Insecure Deserialization"

SRC="${SOURCE_DIR:-.}"
rb_count=$(find "$SRC" -name "*.rb" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rb_count" -eq 0 ]] && { record "SKIP" "P-548 Ruby deserialization" "No Ruby files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.rb" -E "\bYAML\.load\b(?!_file)|\bMarshal\.load\b" "$SRC" 2>/dev/null \
  | grep -vE "/spec/|/test/|/vendor/|safe_load" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-548 Ruby deserialization" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe YAML.load/Marshal.load call(s)" "$sample"; } \
  || record "PASS" "P-548 Ruby deserialization" "No unsafe YAML.load/Marshal.load detected"
