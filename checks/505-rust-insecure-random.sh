#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-505
name: Rust Insecure Random for Cryptographic Purposes
description: Detects use of Rust rand::thread_rng for purposes that require cryptographic randomness (token generation, ID generation, key derivation). The rand crate's thread_rng is not guaranteed to be cryptographically secure across all backends; use rand::rngs::OsRng or getrandom directly for security-sensitive purposes.
category: code-scan
severity: medium
languages: rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A02, CWE:330
cwe: 330
false_positive_rate: medium
performance_class: fast
origin: Rust rand ecosystem — thread_rng is convenient but its cryptographic guarantees are not as strong as OsRng in all configurations.
PRESTON_META

echo "P-505: Rust Insecure Random"

SRC="${SOURCE_DIR:-.}"
rs_count=$(find "$SRC" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rs_count" -eq 0 ]] && { record "SKIP" "P-505 Rust insecure random" "No Rust files found"; return 0 2>/dev/null || true; }

token_random=$(grep -rn --include="*.rs" -E "(token|secret|key|nonce|session_id).*thread_rng|thread_rng.*\.gen[^_]" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/examples/" || true)
secure=$(grep -rln --include="*.rs" -E "rand::rngs::OsRng|getrandom|ring::rand|rand_chacha" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/tests?/" || true)
t_count=$([[ -n "$token_random" ]] && echo "$token_random" | wc -l | tr -d ' ' || echo 0)
s_count=$([[ -n "$secure" ]] && echo "$secure" | wc -l | tr -d ' ' || echo 0)
if [[ ${t_count:-0} -gt 0 && ${s_count:-0} -eq 0 ]]; then
  record "WARN" "P-505 Rust insecure random" "$t_count token/secret usage(s) of thread_rng without OsRng alternative" "$(echo "$secure" | head -10)"
elif [[ ${s_count:-0} -gt 0 ]]; then
  record "PASS" "P-505 Rust insecure random" "$s_count file(s) reference OsRng / getrandom for secure random"
else
  record "PASS" "P-505 Rust insecure random" "No suspicious thread_rng usage on token/secret variables"
fi
