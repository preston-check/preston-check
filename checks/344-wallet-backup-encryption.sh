#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-344
name: Wallet Backup Encryption At Rest
description: Verifies that wallet backups (encrypted JSON keystores, exported seed-phrase files, cloud-sync blobs) are encrypted at rest with strong KDF parameters (Argon2id or scrypt with sufficient cost). Plaintext seed phrases or weakly-protected keystores in cloud sync (iCloud, Google Drive) are routinely extracted by malware and forensic tools.
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
frameworks: PCI-DSS:4.0:3.5, OWASP-MASVS:2.0:CRYPTO-2
cwe: 311
false_positive_rate: medium
performance_class: fast
origin: Multiple major losses (e.g., 2022 Slope wallet breach via unencrypted seed exfiltration to Sentry) demonstrate the cost of unencrypted at-rest wallet data.
PRESTON_META

echo "P-344: Wallet Backup Encryption"

SRC="${SOURCE_DIR:-.}"

backup_handling=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.swift" --include="*.kt" \
  -iE 'walletBackup|exportWallet|exportSeed|backupKeystore|cloud[_-]sync.*wallet|iCloud.*wallet|gdrive.*wallet|encryptedKeystore|saveBackup' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$backup_handling" ]]; then
  record "SKIP" "P-344 Backup encryption" "No wallet backup / export code detected"
  return 0 2>/dev/null || true
fi

strong_kdf=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.swift" --include="*.kt" \
  -iE 'argon2id|argon2|scrypt.*N\s*[:=]\s*[0-9]{4,}|pbkdf2.*iterations.*[0-9]{6,}|aes-256-gcm|chacha20[_-]poly1305|libsodium|nacl\.secretbox' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$strong_kdf" ]]; then
  count=$(echo "$strong_kdf" | wc -l | tr -d ' ')
  record "PASS" "P-344 Backup encryption" "$count file(s) reference strong KDF / authenticated encryption for backups"
else
  record "FAIL" "P-344 Backup encryption" "Wallet backup code without strong KDF (argon2/scrypt) or authenticated encryption (AES-GCM/ChaCha20-Poly1305)"
fi
