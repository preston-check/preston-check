#!/bin/bash
# P-01: Hardcoded secrets in source code
# Preston used exposed JWT secrets and API keys from the git repo.
# This check scans source code for common secret patterns.

echo "P-01: Hardcoded Secrets"

SRC="${SOURCE_DIR:-.}"

# Patterns that indicate hardcoded secrets
PATTERNS=(
  "password\s*=\s*['\"][^'\"]{8,}"
  "secret\s*=\s*['\"][^'\"]{8,}"
  "api_key\s*=\s*['\"][^'\"]{8,}"
  "auth_token\s*=\s*['\"][^'\"]{8,}"
  "AKIA[0-9A-Z]{16}"
  "-----BEGIN.*PRIVATE KEY-----"
)

found=0
for pattern in "${PATTERNS[@]}"; do
  hits=$(grep -rn --include="*.java" --include="*.ts" --include="*.js" --include="*.py" --include="*.yml" --include="*.yaml" \
    --max-count=5 -E "$pattern" "$SRC/Common/src" "$SRC/Registration/src" "$SRC/Client/src" "$SRC/Payments-logic/src" 2>/dev/null \
    | grep -v "test\|Test\|mock\|Mock\|example\|Example\|node_modules\|target\|dist\|\.env\.example" \
    | grep -v "System.getenv\|process.env\|getProperty\|getSecretValue" \
    | grep -v "//\|^\s*\*\|/\*" \
    | grep -v "?secret=\|?api_key=\|+ \"\|URLEncoder\|secretKey\|fxmarketapi" \
    | head -5)
  if [[ -n "$hits" ]]; then
    ((found++))
    if $VERBOSE; then echo "$hits"; fi
  fi
done

if [[ $found -eq 0 ]]; then
  record "PASS" "P-01 Hardcoded secrets" "No hardcoded secrets found in source"
else
  record "FAIL" "P-01 Hardcoded secrets" "$found secret patterns found in source code"
fi
