#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-318
name: Seed Phrase Handling Hygiene
description: Detects code that logs, prints, or stringifies seed phrases or private keys, including stack traces and error messages. Seed phrases or keys that touch logs travel through log-aggregation, monitoring, alerting, and backup systems — every one of which is now a key-exposure surface.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:3.5, OWASP-API:2023:API8, ISO-27001:2022:A.8.10
cwe: 532
false_positive_rate: medium
performance_class: fast
origin: Repeated incidents where seed phrases or keys reached Datadog, Splunk, or Sentry via verbose logging and were exposed in routine log searches.
PRESTON_META

echo "P-318: Seed Phrase Handling Hygiene"

SRC="${SOURCE_DIR:-.}"

# Detect logging of mnemonic / privateKey / seed
hits=$(grep -rnE --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  '(console\.log|logger\.(info|debug|trace|error|warn)|System\.out\.println|print\(|fmt\.Print|log\.(Info|Debug|Print)|println!|eprintln!)\s*\([^)]*(privateKey|mnemonic|seedPhrase|seed_phrase|wallet\.privateKey|recovery_phrase|secretKey)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/tests/|/spec/|node_modules|/mock' || true)

# Stringification anti-patterns
stringify=$(grep -rnE --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  '(JSON\.stringify|util\.inspect)\s*\([^)]*(wallet|privateKey|mnemonic|seed)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|node_modules' || true)

count=0
[[ -n "$hits" ]]      && count=$((count + $(echo "$hits" | wc -l | tr -d ' ')))
[[ -n "$stringify" ]] && count=$((count + $(echo "$stringify" | wc -l | tr -d ' ')))

if [[ $count -eq 0 ]]; then
  record "PASS" "P-318 Seed handling" "No logging or stringification of private keys / mnemonics found"
else
  record "FAIL" "P-318 Seed handling" "$count code path(s) log or stringify private key / mnemonic / seed material" "$(echo "$stringify" | head -10)"
fi
