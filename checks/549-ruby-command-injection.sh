#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-549
name: Ruby Command Injection
description: Detects Kernel#system, exec, backticks, or Open3 with interpolated user input. Shell metacharacters in user-controlled strings allow arbitrary command execution.
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
frameworks: OWASP-Top-10:2021:A03, CWE:78
cwe: 78
false_positive_rate: medium
performance_class: fast
origin: Recurring Ruby RCE class; particularly common in DevOps tooling and admin scripts written in Ruby.
PRESTON_META

echo "P-549: Ruby Command Injection"

SRC="${SOURCE_DIR:-.}"
rb_count=$(find "$SRC" -name "*.rb" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rb_count" -eq 0 ]] && { record "SKIP" "P-549 Ruby command injection" "No Ruby files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.rb" -E "(system|exec|popen|Open3\.[a-z]+|\`)[^#]*#\{" "$SRC" 2>/dev/null \
  | grep -vE "/spec/|/test/|/vendor/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-549 Ruby command injection" "$(echo "$unsafe" | wc -l | tr -d ' ') string-interpolation shell call(s)" "$sample"; } \
  || record "PASS" "P-549 Ruby command injection" "No interpolated shell-call patterns detected"
