#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-474
name: PSD2 Dynamic Linking on Payment Authorization
description: Verifies dynamic linking per PSD2 RTS Article 5 — the SCA authentication code must be unique to the specific amount and payee, computed from those fields, and any subsequent change must invalidate the code. Without dynamic linking, a stolen auth code can be replayed on a different transaction.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PSD2:2018:Art.97, PSD2-RTS:2018:Art.5
false_positive_rate: medium
performance_class: fast
origin: PSD2 RTS Article 5 — dynamic linking. Failure to bind the auth code to amount and payee is a recurring EBA finding.
PRESTON_META

echo "P-474: PSD2 Dynamic Linking"

SRC="${SOURCE_DIR:-.}"
dl=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "dynamicLinking|dynamic[_-]linking|tx[_-]auth[_-]code|signed[_-]payment|payment[_-]signature|HMAC.*amount.*payee|signTx" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$dl" ]] && record "PASS" "P-474 PSD2 dynamic linking" "$(echo "$dl" | wc -l | tr -d ' ') dynamic-linking reference(s)" \
  || record "WARN" "P-474 PSD2 dynamic linking" "No dynamic linking / payment-bound signature pattern detected"
