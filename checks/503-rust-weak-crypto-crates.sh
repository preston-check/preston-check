#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-503
name: Rust Weak Crypto Crates
description: Detects use of deprecated or weak Rust crypto crates — md5, sha-1, rust-crypto (RustSec advisory RUSTSEC-2022-0011 deprecation). Modern fintech code should use rustcrypto's sha2/sha3 family, ring, or ChaCha20-Poly1305.
category: code-scan
severity: high
languages: rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:3.6, CWE:327, NIST-CSF:2.0:PR.DS
cwe: 327
false_positive_rate: low
performance_class: fast
performance_class: fast
origin: RustSec advisory database (RUSTSEC-2022-0011 etc.) flags the rust-crypto crate as unmaintained; md5/sha-1 are cryptographically broken.
PRESTON_META

echo "P-503: Rust Weak Crypto Crates"

SRC="${SOURCE_DIR:-.}"
rs_count=$(find "$SRC" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rs_count" -eq 0 ]] && { record "SKIP" "P-503 Rust weak crypto" "No Rust files found"; return 0 2>/dev/null || true; }

weak=$(grep -rn --include="*.rs" --include="Cargo.toml" -E '^use\s+md5|^use\s+sha1::|rust-crypto\s*=|"md5"\s*=|"sha-1"\s*=' "$SRC" 2>/dev/null \
  | grep -vE "/tests?/" || true)
[[ -n "$weak" ]] && record "FAIL" "P-503 Rust weak crypto" "$(echo "$weak" | wc -l | tr -d ' ') weak/deprecated crypto reference(s)" \
  || record "PASS" "P-503 Rust weak crypto" "No deprecated md5/sha-1/rust-crypto references"
