#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-414
name: NYDFS Part 500 Nonpublic Information Encryption
description: Verifies encryption controls for nonpublic information at rest and in transit per 23 NYCRR 500.15. The 2023 amendments tighten the standard, removing some legacy alternatives.
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
frameworks: NYDFS:23NYCRR500:500.15, PCI-DSS:4.0:3.5, NIST-CSF:2.0:PR.DS-1
false_positive_rate: high
performance_class: fast
origin: NYDFS Part 500.15 — encryption of nonpublic information at rest and in transit.
PRESTON_META

echo "P-414: NYDFS Encryption (nonpublic info)"

SRC="${SOURCE_DIR:-.}"
weak=$(grep -rln --include="*.java" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE "DES[_-]CBC|RC4|MD5\b|SHA1\b|SSLv[23]|TLSv1\.0|TLSv1\.1" "$SRC" 2>/dev/null | grep -vE "/test/|node_modules" || true)
strong=$(grep -rln --include="*.java" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE "AES[_-]GCM|ChaCha20[_-]Poly1305|TLSv1\.[23]|TLS_AES|argon2|scrypt|bcrypt" "$SRC" 2>/dev/null | grep -vE "/test/|node_modules" || true)
weak_count=$([[ -n "$weak" ]] && echo "$weak" | wc -l | tr -d ' ' || echo 0)
strong_count=$([[ -n "$strong" ]] && echo "$strong" | wc -l | tr -d ' ' || echo 0)
if [[ ${weak_count:-0} -gt 0 && ${strong_count:-0} -eq 0 ]]; then
  record "FAIL" "P-414 NYDFS encryption" "$weak_count weak-crypto reference(s) and no strong-crypto reference"
elif [[ ${weak_count:-0} -gt 0 ]]; then
  record "WARN" "P-414 NYDFS encryption" "$weak_count weak-crypto reference(s); $strong_count strong-crypto reference(s)"
else
  record "PASS" "P-414 NYDFS encryption" "Strong-only crypto references ($strong_count)"
fi
