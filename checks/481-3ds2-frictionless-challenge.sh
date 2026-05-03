#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-481
name: 3DS2 Frictionless and Challenge Flow Handling
description: Verifies handling of both 3DS2 frictionless and challenge flows. Frictionless transactions (low risk) skip user interaction; challenge transactions require interactive authentication. Treating only one path produces incorrect SCA exemption claims.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: EMVCo-3DS:2.3, PSD2-RTS:2018:Art.18
false_positive_rate: medium
performance_class: fast
origin: EMVCo 3DS 2.x — frictionless and challenge flow handling.
PRESTON_META

echo "P-481: 3DS2 Frictionless / Challenge Flow"

SRC="${SOURCE_DIR:-.}"
flows=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "frictionless|challengeRequired|transStatus[_-]?[YN]|acs[_-]challenge|3ds.*method[_-]url|threeDSMethod" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$flows" ]] && record "PASS" "P-481 3DS2 flows" "$(echo "$flows" | wc -l | tr -d ' ') frictionless/challenge handling reference(s)" \
  || record "WARN" "P-481 3DS2 flows" "No frictionless/challenge flow handling detected"
