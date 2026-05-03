#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-442
name: MAS TRM Customer Authentication
description: Verifies adherence to MAS Notice on Risk Management and Operational Standards (NRMOS) for customer authentication — strong authentication for high-risk transactions, transaction signing, and out-of-band notifications.
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
frameworks: MAS-TRM:2021:CustAuth, NIST-CSF:2.0:PR.AA, OWASP-MASVS:2.0:AUTH-1
false_positive_rate: medium
performance_class: fast
origin: MAS TRM customer authentication requirements; closely tracks PSD2 SCA but with Singapore-specific implementation notes.
PRESTON_META

echo "P-442: MAS Customer Authentication"

SRC="${SOURCE_DIR:-.}"
auth=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "transactionSigning|out[_-]of[_-]band|push[_-]auth|transaction[_-]2fa|SMS[_-]OTP|HKD[_-]auth|biometric.*authenticate" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$auth" ]] && record "PASS" "P-442 MAS customer auth" "$(echo "$auth" | wc -l | tr -d ' ') strong-customer-auth reference(s)" \
  || record "WARN" "P-442 MAS customer auth" "No strong customer authentication patterns detected"
