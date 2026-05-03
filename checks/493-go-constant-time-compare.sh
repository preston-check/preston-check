#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-493
name: Go Constant-Time Comparison for Secrets
description: Detects Go code comparing secrets, MAC outputs, or API keys with == / strings.Compare instead of crypto/subtle.ConstantTimeCompare. Non-constant-time comparisons leak length and content via timing side-channels.
category: code-scan
severity: medium
languages: go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A02, CWE:208
cwe: 208
false_positive_rate: medium
performance_class: fast
origin: Timing-based attacks on HMAC/token comparison; mitigated by crypto/subtle.ConstantTimeCompare.
PRESTON_META

echo "P-493: Go Constant-Time Comparison"

SRC="${SOURCE_DIR:-.}"
go_count=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$go_count" -eq 0 ]] && { record "SKIP" "P-493 Go const-time" "No Go files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.go" -E "(token|secret|hmac|signature|apikey|api_key)\s*==\s*[a-zA-Z_]" "$SRC" 2>/dev/null \
  | grep -vE "/vendor/|_test\.go|/test/" || true)
const_time=$(grep -rln --include="*.go" -E "subtle\.ConstantTimeCompare|crypto/subtle" "$SRC" 2>/dev/null | grep -vE "/vendor/|_test\.go" || true)
u_count=$([[ -n "$unsafe" ]] && echo "$unsafe" | wc -l | tr -d ' ' || echo 0)
c_count=$([[ -n "$const_time" ]] && echo "$const_time" | wc -l | tr -d ' ' || echo 0)
if [[ ${u_count:-0} -gt 0 && ${c_count:-0} -eq 0 ]]; then
  record "FAIL" "P-493 Go const-time" "$u_count timing-vulnerable comparison(s); no crypto/subtle import"
elif [[ ${c_count:-0} -gt 0 ]]; then
  record "PASS" "P-493 Go const-time" "$c_count file(s) use crypto/subtle constant-time comparison"
else
  record "WARN" "P-493 Go const-time" "No secret comparisons detected; ensure crypto/subtle for any future ones"
fi
