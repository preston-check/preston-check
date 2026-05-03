#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-42
name: CI/CD Security
description: Checks credentials in scripts, curl/bash, SSL disabled.
category: infra-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.5.3, PCI-DSS:4.0:6.5.4, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.31, CIS-v8:16.7
PRESTON_META

# P-42: CI/CD Pipeline Security
echo "P-42: CI/CD Security"
SRC="${SOURCE_DIR:-.}"
creds_scripts=$(grep -rn --include="*.sh" "password\|secret\|api_key\|AWS_ACCESS\|AWS_SECRET" "$SRC" 2>/dev/null | grep -i "deploy\|build\|setup\|install" | grep -v "getenv\|System\|test\|example\|#\|echo\|\${\|export" | head -5)
if [[ -z "$creds_scripts" ]]; then record "PASS" "P-42 No creds in scripts" "No credentials in deploy/build scripts"; else count=$(echo "$creds_scripts" | wc -l); record "WARN" "P-42 Creds in scripts" "$count deploy/build scripts may contain credentials"; fi
curl_bash=$(grep -rn --include="*.sh" "curl.*|.*bash\|curl.*|.*sh\|wget.*|.*bash" "$SRC" 2>/dev/null | grep -v "#\|test\|Test" | head -3)
if [[ -z "$curl_bash" ]]; then record "PASS" "P-42 No curl|bash" "No curl-pipe-to-bash patterns"; else record "FAIL" "P-42 curl|bash" "curl|bash pattern found — supply chain risk"; fi
ssl_skip=$(grep -rn --include="*.sh" --include="*.java" "insecure\|ssl.*verify.*false\|no-check-certificate\|trustAllCerts\|ALLOW_ALL" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#\|self.*signed\|buildSelfSigned" | head -3)
if [[ -z "$ssl_skip" ]]; then record "PASS" "P-42 SSL verification" "No SSL verification bypasses"; else record "WARN" "P-42 SSL verification" "SSL verification disabled in some scripts"; fi
