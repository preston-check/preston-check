#!/bin/bash
# P-42: CI/CD Pipeline Security
echo "P-42: CI/CD Security"
SRC="${SOURCE_DIR:-.}"
creds_scripts=$(grep -rn --include="*.sh" "password\|secret\|api_key\|AWS_ACCESS\|AWS_SECRET" "$SRC" 2>/dev/null | grep -i "deploy\|build\|setup\|install" | grep -v "getenv\|System\|test\|example\|#\|echo\|\${\|export" | head -5)
if [[ -z "$creds_scripts" ]]; then record "PASS" "P-42 No creds in scripts" "No credentials in deploy/build scripts"; else count=$(echo "$creds_scripts" | wc -l); record "WARN" "P-42 Creds in scripts" "$count deploy/build scripts may contain credentials"; fi
curl_bash=$(grep -rn --include="*.sh" "curl.*|.*bash\|curl.*|.*sh\|wget.*|.*bash" "$SRC" 2>/dev/null | grep -v "#\|test\|Test" | head -3)
if [[ -z "$curl_bash" ]]; then record "PASS" "P-42 No curl|bash" "No curl-pipe-to-bash patterns"; else record "FAIL" "P-42 curl|bash" "curl|bash pattern found — supply chain risk"; fi
ssl_skip=$(grep -rn --include="*.sh" --include="*.java" "insecure\|ssl.*verify.*false\|no-check-certificate\|trustAllCerts\|ALLOW_ALL" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#\|self.*signed\|buildSelfSigned" | head -3)
if [[ -z "$ssl_skip" ]]; then record "PASS" "P-42 SSL verification" "No SSL verification bypasses"; else record "WARN" "P-42 SSL verification" "SSL verification disabled in some scripts"; fi
