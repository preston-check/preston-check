#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-08
name: Input Validation
description: Checks for SQL injection, command injection patterns.
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
frameworks: PCI-DSS:4.0:6.2.4, PCI-DSS:4.0:6.5.1, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.26, OWASP-API:2023:API10:2023, CIS-v8:16.9
PRESTON_META

# P-08: Input validation and injection prevention
# Check that API endpoints validate input and use parameterized queries.

echo "P-08: Input Validation"

SRC="${SOURCE_DIR:-.}"

# Check for string concatenation in SQL (injection risk)
sql_concat=$(grep -rn --include="*.java" \
  "\"SELECT.*\" +\|\"INSERT.*\" +\|\"UPDATE.*\" +\|\"DELETE.*\" +" \
  "$SRC" 2>/dev/null \
  | grep -v "PreparedStatement\|prepareStatement\|test\|Test\|target\|node_modules\|//\|log\." \
  | grep -v "\.sql\|migration\|CREATE TABLE\|ALTER TABLE" \
  | head -10)

if [[ -z "$sql_concat" ]]; then
  record "PASS" "P-08 SQL injection" "No string-concatenated SQL found"
else
  count=$(echo "$sql_concat" | wc -l)
  record "WARN" "P-08 SQL injection" "$count potential SQL concatenation sites (verify parameterized)"
fi

# Check for eval/exec patterns (command injection)
# Exclude: jedis.eval (Redis Lua scripting, not OS command execution)
#          ProcessBuilder with input validation (SAFE_TEST_CLASS, Pattern.matches, whitelist)
exec_patterns=$(grep -rn --include="*.java" --include="*.ts" --include="*.js" \
  "Runtime.getRuntime().exec\|ProcessBuilder\|eval(\|Function(\|child_process\|execSync\|spawnSync" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|dist\|ConfigurationManager\|genJar\|deploy\|setup\|//\|/\*\|\.sh\|\.md\|vendor\|build\|Website\|public_\|jquery\|\.min\.js" \
  | grep -v "jedis\.eval\|redis.*eval\|Jedis.*eval" \
  | while read -r line; do
      file=$(echo "$line" | cut -d: -f1)
      # If file uses ProcessBuilder, check if it also has input validation
      if echo "$line" | grep -q "ProcessBuilder"; then
        if grep -q "SAFE_.*Pattern\|Pattern.*matches\|whitelist\|\.matches(" "$file" 2>/dev/null; then
          continue
        fi
      fi
      echo "$line"
    done \
  | head -5)

if [[ -z "$exec_patterns" ]]; then
  record "PASS" "P-08 Command injection" "No exec/eval patterns found"
else
  count=$(echo "$exec_patterns" | wc -l)
  record "FAIL" "P-08 Command injection" "$count potential command execution sites"
fi
