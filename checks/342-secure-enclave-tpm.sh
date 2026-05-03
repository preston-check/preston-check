#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-342
name: Secure Enclave / TPM-Backed Key Storage
description: Verifies that mobile and desktop wallet applications generate and store key material in platform secure enclaves (iOS Secure Enclave / Keychain, Android Keystore / StrongBox, Windows TPM, Linux TPM2) rather than in application-readable storage. Keys in secure enclaves cannot be exported even with root/admin access on the device.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, ISO-27001:2022:A.10.1, OWASP-MASVS:2.0:CRYPTO-1
cwe: 312
false_positive_rate: medium
performance_class: fast
origin: Mobile wallet best practice; iOS / Android both provide hardware-backed key storage that meaningfully raises the bar on extraction even for compromised devices.
PRESTON_META

echo "P-342: Secure Enclave / TPM"

SRC="${SOURCE_DIR:-.}"

enclave_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.go" --include="*.rs" \
  -iE 'secEnclave|SecureEnclave|kSecAttrTokenIDSecureEnclave|AndroidKeystore|StrongBox|setIsStrongBoxBacked|TPM2|tpm[_-]signing|microsoft[_-]CNG|wincred|keychain[_-]access|kSecAttrSynchronizable' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Mobile wallet code detection
mobile=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.tsx" \
  -iE 'mobile[_-]wallet|expo|react-native|flutter' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$mobile" ]] && [[ -z "$enclave_refs" ]]; then
  record "SKIP" "P-342 Secure enclave" "No mobile wallet or enclave-relevant code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$enclave_refs" ]]; then
  count=$(echo "$enclave_refs" | wc -l | tr -d ' ')
  record "PASS" "P-342 Secure enclave" "$count file(s) reference Secure Enclave / Keystore / TPM-backed key storage"
else
  record "WARN" "P-342 Secure enclave" "Mobile wallet code without Secure Enclave / Keystore / TPM references"
fi
