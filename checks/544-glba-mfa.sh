#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-544
name: GLBA MFA on Customer Information Access
description: Verifies MFA enforcement on access to customer information per GLBA Safeguards Rule 16 CFR 314.4(c)(5). MFA is required for any individual accessing customer information.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: GLBA-Safeguards:16CFR314.4.c.5, NIST-CSF:2.0:PR.AA, PCI-DSS:4.0:8.4.2
cwe: 308
false_positive_rate: medium
performance_class: fast
origin: GLBA Safeguards Rule MFA requirement.
PRESTON_META

echo "P-544: GLBA MFA"

SRC="${SOURCE_DIR:-.}"
mfa=$(grep -rln --include="*.java" --include="*.kt" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.rb" --include="*.cs" --include="*.php" \
  -iE "mfa|2fa|two[_-]factor|webauthn|fido2|totp" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$mfa" ]] && record "PASS" "P-544 GLBA MFA" "$(echo "$mfa" | wc -l | tr -d ' ') MFA reference(s)" \
  || record "WARN" "P-544 GLBA MFA" "No MFA references found in source code"
