#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-346
name: In-Process Key Memory Hygiene
description: Verifies that languages allowing memory control (Go, Rust, C/C++, Java with byte arrays) actively wipe key material from memory after use rather than relying on garbage collection. Long-lived process memory holding even briefly-used key material is exposed to memory dumps, core files, and process-injection malware.
category: code-scan
severity: medium
languages: java, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, OWASP-MASVS:2.0:CRYPTO-1
cwe: 226
false_positive_rate: high
performance_class: fast
origin: Memory-dump and core-file forensic recovery of cryptographic material is a documented attack technique, especially in long-running services.
PRESTON_META

echo "P-346: Memory Wiping for Keys"

SRC="${SOURCE_DIR:-.}"

# Find code that loads keys
key_loaders=$(grep -rln --include="*.java" --include="*.go" --include="*.rs" \
  -iE 'PrivateKey|privateKey|signingKey|secretKey|byte\[\].*key|\[\]byte.*key' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|vendor/|/test/' || true)

if [[ -z "$key_loaders" ]]; then
  record "SKIP" "P-346 Memory wiping" "No in-process key handling detected (Java/Go/Rust)"
  return 0 2>/dev/null || true
fi

# Look for explicit zeroing / Zeroize / Arrays.fill / mlock
zeroing=$(grep -rln --include="*.java" --include="*.go" --include="*.rs" \
  -iE 'Arrays\.fill\s*\([^)]*key[^)]*,\s*\(\s*byte\s*\)\s*0|crypto/subtle\.ConstantTimeCompare|zeroize|Zeroize|secrecy::|memset.*key.*0|BurnAfterRead|sodium_memzero|explicit_bzero|mlock' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|vendor/|/test/' || true)

if [[ -n "$zeroing" ]]; then
  count=$(echo "$zeroing" | wc -l | tr -d ' ')
  record "PASS" "P-346 Memory wiping" "$count file(s) explicitly wipe / mlock key material"
else
  record "WARN" "P-346 Memory wiping" "In-process key handling without explicit memory wiping (consider Zeroize, Arrays.fill, sodium_memzero)"
fi
