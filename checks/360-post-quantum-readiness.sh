#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-360
name: Post-Quantum Cryptography Readiness Assessment
description: Surveys the codebase for cryptographic algorithm choices and flags reliance on quantum-vulnerable primitives (RSA, ECDSA, ECDH, classic Diffie-Hellman) without documented post-quantum migration plans. NIST finalized the first PQC standards (ML-DSA / FIPS 204, ML-KEM / FIPS 203) in 2024; financial institutions are expected to publish migration roadmaps.
category: compliance-evidence
severity: low
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, NIST-FIPS:204, NIST-FIPS:203, NIST-FIPS:205
cwe: 327
false_positive_rate: high
performance_class: fast
origin: NIST finalized FIPS 203/204/205 in 2024. Bank regulators (OCC, Federal Reserve, ECB) have begun signaling expected migration timelines; institutional custody is among the first wave of mandates.
PRESTON_META

echo "P-360: Post-Quantum Cryptography Readiness"

SRC="${SOURCE_DIR:-.}"

# Find quantum-vulnerable crypto
classical=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.sol" \
  -iE 'RSA[_-]2048|RSA[_-]4096|secp256k1|secp256r1|prime256v1|ECDSA|ECDH|p256\.|p384\.|p521\.|ed25519|x25519' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$classical" ]]; then
  record "SKIP" "P-360 PQC readiness" "No classical-cryptography references detected"
  return 0 2>/dev/null || true
fi

# Look for PQC migration evidence
pqc=$(grep -rln --include="*.md" --include="*.txt" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'post[_-]quantum|PQC|FIPS[_-]?203|FIPS[_-]?204|FIPS[_-]?205|ML[_-]DSA|ML[_-]KEM|SLH[_-]DSA|kyber|dilithium|falcon|sphincs|crystals|liboqs|hybrid[_-]signature' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

cls_count=$(echo "$classical" | wc -l | tr -d ' ')

if [[ -n "$pqc" ]]; then
  pqc_count=$(echo "$pqc" | wc -l | tr -d ' ')
  record "PASS" "P-360 PQC readiness" "$cls_count classical reference(s); $pqc_count PQC migration reference(s) present"
else
  record "WARN" "P-360 PQC readiness" "$cls_count classical-crypto reference(s) without documented PQC migration plan (FIPS 203/204/205, ML-KEM/ML-DSA)"
fi
