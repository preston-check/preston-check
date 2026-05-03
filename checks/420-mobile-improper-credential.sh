#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-420
name: OWASP Mobile M1 — Improper Credential Usage
description: Detects mobile-specific credential mishandling — hardcoded credentials in mobile sources, credentials in SharedPreferences without encryption, credentials in NSUserDefaults / iOS plist, credentials in app bundle resources.
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
frameworks: OWASP-MAS:2024:M1, OWASP-MASVS:2.0:STORAGE-1, NIST-CSF:2.0:PR.DS
false_positive_rate: medium
performance_class: fast
origin: OWASP Mobile Top 10 (2024) M1 — Improper Credential Usage; routinely found in app pen-tests.
PRESTON_META

echo "P-420: Mobile Improper Credential Usage"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" --include="*.tsx" --include="*.plist" \
  -iE "SharedPreferences[^.]*putString[^)]*password|NSUserDefaults.*setObject.*password|api_?key\s*=\s*\"[A-Za-z0-9]{16,}|credential.*hardcoded|encryptedSharedPreferences|EncryptedFile" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)
secure=$(grep -rln --include="*.swift" --include="*.kt" --include="*.java" --include="*.dart" \
  -iE "Keychain|Keystore|AndroidKeystore|EncryptedSharedPreferences|SecureStorage|biometric_storage" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)
hits_count=$([[ -n "$hits" ]] && echo "$hits" | wc -l | tr -d ' ' || echo 0)
sec_count=$([[ -n "$secure" ]] && echo "$secure" | wc -l | tr -d ' ' || echo 0)
if [[ ${hits_count:-0} -eq 0 && ${sec_count:-0} -gt 0 ]]; then
  record "PASS" "P-420 mobile credentials" "$sec_count secure-storage reference(s)"
elif [[ ${hits_count:-0} -gt 0 ]]; then
  record "FAIL" "P-420 mobile credentials" "$hits_count credential mishandling pattern(s) detected" "$(echo "$secure" | head -10)"
else
  record "SKIP" "P-420 mobile credentials" "No mobile source code detected"
fi
