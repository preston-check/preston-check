#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-315
name: Cold Wallet Air-Gap Discipline
description: Verifies that cold wallet operations follow an offline-signing pattern (sign on air-gapped device, broadcast online) rather than holding cold-wallet keys on internet-connected machines. Documentation references and code paths should distinguish hot/warm/cold wallet operations clearly.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, ISO-27001:2022:A.10.1
cwe: 320
false_positive_rate: high
performance_class: fast
origin: Industry standard custody practice. Mt. Gox (2014, $450M), QuadrigaCX (2019, $190M), and others demonstrated the catastrophic risk of online-resident cold-storage keys.
PRESTON_META

echo "P-315: Cold Wallet Air-Gap Discipline"

SRC="${SOURCE_DIR:-.}"

# Look for hot/warm/cold wallet distinction in code or config
wallet_tier_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.md" --include="*.yml" --include="*.yaml" \
  -iE 'cold[_-]?wallet|warm[_-]?wallet|hot[_-]?wallet|airgap|air[_-]gapped|offline[_-]signing|cold[_-]storage|cold[_-]signer' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

# Look for cold-wallet key material online (anti-pattern: cold wallet PK in env or file)
cold_online=$(grep -rnE --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.env" --include="*.yml" --include="*.yaml" \
  '(COLD[_-]?WALLET[_-]?KEY|COLD[_-]?STORAGE[_-]?KEY|COLD[_-]?PRIVATE[_-]?KEY)\s*=' "$SRC" 2>/dev/null \
  | grep -vE '\.example|/test/|/tests/|/mock|node_modules' || true)

if [[ -n "$cold_online" ]]; then
  count=$(echo "$cold_online" | wc -l | tr -d ' ')
  record "FAIL" "P-315 Cold wallet air-gap" "$count occurrence(s) of cold-wallet key material in online config — defeats air-gap" "$(echo "$cold_online" | head -10)"
elif [[ -z "$wallet_tier_refs" ]]; then
  record "SKIP" "P-315 Cold wallet air-gap" "No hot/warm/cold wallet terminology found; manual review needed"
else
  count=$(echo "$wallet_tier_refs" | wc -l | tr -d ' ')
  record "PASS" "P-315 Cold wallet air-gap" "$count reference(s) to wallet tiering or air-gap discipline"
fi
