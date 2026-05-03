#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-470
name: PSD2 SCA Triggers (Account Access + Payments)
description: Verifies Strong Customer Authentication is enforced on PSD2-mandated triggers — initial account access (RTS Article 10), every electronic payment initiation, and every action that may imply a risk of payment fraud or other abuses.
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
frameworks: PSD2:2018:Art.97, PSD2-RTS:2018:Art.2, NIST-CSF:2.0:PR.AA
false_positive_rate: medium
performance_class: fast
origin: PSD2 Article 97 + EBA RTS on Strong Customer Authentication (Commission Delegated Regulation 2018/389).
PRESTON_META

echo "P-470: PSD2 SCA Triggers"

SRC="${SOURCE_DIR:-.}"
sca=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "SCA[_-]check|strongCustomerAuth|sca[_-]required|requireSCA|psd2[_-]sca|threeDS|3DS2|payment[_-]initiation[_-]auth" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$sca" ]] && record "PASS" "P-470 PSD2 SCA triggers" "$(echo "$sca" | wc -l | tr -d ' ') SCA reference(s)" \
  || record "WARN" "P-470 PSD2 SCA triggers" "No SCA enforcement patterns detected"
