#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-327
name: Mixer / Privacy Tool Provenance Check
description: Verifies the platform flags or blocks transactions involving funds with mixer or privacy-tool provenance (Tornado Cash, Wasabi CoinJoin, Samourai Whirlpool, ChipMixer, Sinbad). OFAC has sanctioned several mixer addresses; touching mixed funds can trigger compliance violations and regulatory enforcement.
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
frameworks: OFAC:2024, FATF:2023:Rec.16, FinCEN:2023
cwe: 20
false_positive_rate: medium
performance_class: fast
origin: OFAC sanctioned Tornado Cash (August 2022), Sinbad (November 2023), and others. US-based platforms processing mixer-derived funds face direct enforcement risk.
PRESTON_META

echo "P-327: Mixer / Privacy Tool Detection"

SRC="${SOURCE_DIR:-.}"

mixer_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'tornado[_-]cash|tornadoCash|wasabi[_-]wallet|samourai[_-]whirlpool|whirlpool[_-]mix|chipMixer|chip[_-]mixer|sinbad[_-]io|mixer[_-]provenance|coinjoin[_-]check|privacy[_-]coin[_-]check|mixer[_-]detection' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find any address screening / receipt code
screening=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'screenAddress|isClean|riskScore|provenance|sourceOfFunds|chainTrace|fundsTrace' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$mixer_refs" ]]; then
  count=$(echo "$mixer_refs" | wc -l | tr -d ' ')
  record "PASS" "P-327 Mixer detection" "$count file(s) reference mixer / privacy-tool detection patterns"
elif [[ -n "$screening" ]]; then
  record "WARN" "P-327 Mixer detection" "Address screening present but no explicit mixer/privacy-tool detection — consider augmenting"
else
  record "WARN" "P-327 Mixer detection" "No mixer/privacy-tool detection logic found"
fi
