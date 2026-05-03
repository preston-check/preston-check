#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-701
name: Initializer Function Protection
description: Detects upgradeable contracts whose initialize() functions lack the `initializer` modifier or whose implementation contracts can be initialized by attackers. Wormhole bridge ($320M, Feb 2022) was compromised through unprotected initializer on the implementation contract.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC01, CWE:1188
cwe: 1188
false_positive_rate: medium
performance_class: fast
origin: Wormhole bridge incident, OpenZeppelin Initializable issues — repeated exploit pattern over multiple years.
PRESTON_META

echo "P-701: Initializer Function Protection"

SRC="${SOURCE_DIR:-.}"
init_files=$(grep -rl --include="*.sol" -E "function\s+initialize\s*\(" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/mock/|node_modules" || true)

if [[ -z "$init_files" ]]; then
  record "SKIP" "P-701 Initializer protection" "No initialize() functions detected"
  return 0 2>/dev/null || true
fi

unprotected=0
unprotected_list=""
for f in $init_files; do
  has_modifier=$(grep -cE 'function\s+initialize\s*\([^)]*\)[^{]*initializer' "$f" 2>/dev/null || echo 0)
  has_disable=$(grep -cE '_disableInitializers\s*\(' "$f" 2>/dev/null || echo 0)
  has_reinit=$(grep -cE 'reinitializer\s*\(' "$f" 2>/dev/null || echo 0)
  if [[ ${has_modifier:-0} -eq 0 && ${has_disable:-0} -eq 0 && ${has_reinit:-0} -eq 0 ]]; then
    ((unprotected++))
    unprotected_list+="$f"$'\n'
  fi
done

if [[ $unprotected -eq 0 ]]; then
  total=$(echo "$init_files" | wc -l | tr -d ' ')
  record "PASS" "P-701 Initializer protection" "$total file(s) all use initializer/_disableInitializers/reinitializer modifier"
else
  sample=$(printf '%s' "$unprotected_list" | head -10)
  record "FAIL" "P-701 Initializer protection" "$unprotected initialize() function(s) without protection — Wormhole-class vulnerability" "$sample"
fi
