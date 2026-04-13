#!/bin/bash
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
exec_patterns=$(grep -rn --include="*.java" --include="*.ts" --include="*.js" \
  "Runtime.getRuntime().exec\|ProcessBuilder\|eval(\|Function(\|child_process\|execSync\|spawnSync" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|dist\|ConfigurationManager\|genJar\|deploy\|setup" \
  | head -5)

if [[ -z "$exec_patterns" ]]; then
  record "PASS" "P-08 Command injection" "No exec/eval patterns found"
else
  count=$(echo "$exec_patterns" | wc -l)
  record "FAIL" "P-08 Command injection" "$count potential command execution sites"
fi
