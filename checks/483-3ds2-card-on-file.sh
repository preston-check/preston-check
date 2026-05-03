#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-483
name: 3DS2 Card-on-File Initial Authentication
description: Verifies that card-on-file transactions correctly distinguish initial cardholder-initiated (SCA-required) from subsequent merchant-initiated (no SCA on cards stored after initial CIT). Misclassification leads to either failed transactions or compliance breaches.
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
frameworks: PSD2-RTS:2018, EMVCo-3DS:2.3
false_positive_rate: medium
performance_class: fast
origin: 3DS2 + PSD2 — card-on-file (CIT vs MIT) distinction is critical for recurring-billing fintechs.
PRESTON_META

echo "P-483: 3DS2 Card-on-File"

SRC="${SOURCE_DIR:-.}"
cof=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "card[_-]on[_-]file|cardholder[_-]initiated|merchant[_-]initiated|CIT|MIT|stored[_-]credential|setup[_-]future[_-]usage" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$cof" ]] && record "PASS" "P-483 3DS2 card-on-file" "$(echo "$cof" | wc -l | tr -d ' ') CoF / CIT-MIT reference(s)" \
  || record "WARN" "P-483 3DS2 card-on-file" "No card-on-file / CIT-MIT distinction detected"
