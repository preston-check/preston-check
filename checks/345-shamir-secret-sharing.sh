#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-345
name: Shamir's Secret Sharing for Backup Distribution
description: Verifies that high-value wallet backups use Shamir's Secret Sharing (SLIP-39, sssa, ssss) or equivalent threshold-secret-distribution schemes rather than single-location backups. SSS distributes the seed across N shares any K of which can reconstruct, preventing single-point-of-failure on backup compromise or loss.
category: code-scan
severity: low
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS
cwe: 1391
false_positive_rate: high
performance_class: fast
origin: SLIP-39 (Trezor's Shamir backup) and similar schemes are the institutional-custody norm; SSS provides survivability without concentrating risk in one backup location.
PRESTON_META

echo "P-345: Shamir's Secret Sharing"

SRC="${SOURCE_DIR:-.}"

sss_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'shamir|sssa|ssss|slip[_-]?39|slip39|secret[_-]sharing|threshold[_-]secret|trezor[_-]shamir|sscombine|sssplit' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find backup/recovery flows
recovery=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'walletBackup|recoverySeed|restoreWallet|backupShard|recoveryShard' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$recovery" ]]; then
  record "SKIP" "P-345 Shamir SSS" "No backup/recovery flows detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$sss_refs" ]]; then
  count=$(echo "$sss_refs" | wc -l | tr -d ' ')
  record "PASS" "P-345 Shamir SSS" "$count file(s) reference Shamir Secret Sharing or SLIP-39"
else
  record "WARN" "P-345 Shamir SSS" "Backup/recovery flows without SSS or SLIP-39 distribution"
fi
