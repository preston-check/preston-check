#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-480
name: 3DS2 Integration Presence
description: Detects integration with 3-D Secure 2 (EMVCo 3DS) for card-not-present transactions. PSD2 SCA exemptions for low-value and TRA paths still require 3DS2 channel availability for fallback challenge flows.
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
frameworks: PSD2:2018:Art.97, PCI-3DS:1.3, EMVCo-3DS:2.3
false_positive_rate: medium
performance_class: fast
origin: EMVCo 3DS 2.x specification + PCI 3DS Core Security Standard. Required for EU card-not-present payments under PSD2.
PRESTON_META

echo "P-480: 3DS2 Integration"

SRC="${SOURCE_DIR:-.}"
threeDS=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "3DS2|3D[_-]Secure|threeds|threeDsAuthenticate|ds[_-]transaction|acsUrl|cavv|eci|directoryServerID|messageVersion[_-]?2|authenticationValue" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$threeDS" ]] && record "PASS" "P-480 3DS2 integration" "$(echo "$threeDS" | wc -l | tr -d ' ') 3DS2 reference(s)" \
  || record "WARN" "P-480 3DS2 integration" "No 3DS2 / 3-D Secure integration detected"
