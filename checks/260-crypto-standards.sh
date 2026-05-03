#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-260
name: Crypto Standards
description: Crypto Standards security check (see COMPLIANCE_MAPPING.md for details).
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-260: Cryptographic Standards
echo "P-260: Cryptographic Standards"
SRC="${SOURCE_DIR:-.}"

weak_hash=$(grep -rn --include="$SRC_EXT" 'MD5\|SHA-1\b\|SHA1\b' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|SHA-256\|SHA256\|SHA-512\|HmacSHA256\|google_authenticator\|TOTP\|SupefinaSign\|comment\|//")
if [[ -z "$weak_hash" ]]; then record "PASS" "P-260 Hash strength" "No weak hash algorithms (excluding external protocol requirements)"; else count=$(echo "$weak_hash" | wc -l | tr -d ' '); record "WARN" "P-260 Hash strength" "$count weak hash patterns — prefer SHA-256 minimum"; echo "$weak_hash" | head -5; fi

secure_random=$(grep -rn --include="$SRC_EXT" 'SecureRandom\|crypto\.randomBytes\|os\.urandom' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
unsafe_random=$(grep -rn --include="$SRC_EXT" 'java\.util\.Random\b\|Math\.random()' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|SecureRandom\|//\|/\*" | head -3)
if [[ -n "$secure_random" ]] && [[ -z "$unsafe_random" ]]; then record "PASS" "P-260 Secure random" "SecureRandom used, no unsafe Random"; elif [[ -n "$unsafe_random" ]]; then record "WARN" "P-260 Secure random" "java.util.Random found — use SecureRandom for security-sensitive operations"; else record "WARN" "P-260 Secure random" "No explicit SecureRandom usage found"; fi

key_length=$(grep -rn --include="$SRC_EXT" 'keySize\|key.*size\|key.*length\|RSA.*1024\|RSA.*512' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
weak_key=$(echo "$key_length" | grep -i '512\|768\|1024' | head -3)
if [[ -z "$weak_key" ]]; then record "PASS" "P-260 Key length" "No weak key lengths found"; else record "WARN" "P-260 Key length" "Weak key lengths found — RSA must be >= 2048 bits"; fi

timing_safe=$(grep -rn --include="$SRC_EXT" 'MessageDigest.isEqual\|constantTimeEquals\|timingSafeEqual\|crypto\.timingSafeEqual\|hmac\.equals\b' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$timing_safe" ]]; then record "PASS" "P-260 Timing-safe comparison" "Constant-time string comparison found"; else record "WARN" "P-260 Timing-safe comparison" "No timing-safe comparison — HMAC/token verification vulnerable to timing attacks"; fi
