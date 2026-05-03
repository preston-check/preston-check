#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-49
name: Git History Secrets
description: Checks .env files, key files ever committed in git history.
category: code-scan
severity: critical
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.6.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.4, NIST-CSF:2.0:PR.DS-1, CIS-v8:16.12
PRESTON_META


# P-49: Secrets in Git History
echo "P-49: Git History Secrets"
SRC="${SOURCE_DIR:-.}"
if ! git -C "$SRC" rev-parse --is-inside-work-tree &>/dev/null; then record "SKIP" "P-49 Git history" "Not a git repository"; return 0 2>/dev/null || exit 0; fi
env_history=$(git -C "$SRC" log --all --diff-filter=A --name-only --pretty=format: 2>/dev/null | grep -E "\.env$|\.env\.local$|\.env\.production$" | sort -u)
if [[ -z "$env_history" ]]; then record "PASS" "P-49 No .env in history" "No .env files ever committed"; else count=$(echo "$env_history" | wc -l); record "WARN" "P-49 .env in history" "$count .env files in git history (may contain secrets)"; echo "$env_history" | head -5; fi
key_history=$(git -C "$SRC" log --all --diff-filter=A --name-only --pretty=format: 2>/dev/null | grep -E "\.pem$|\.key$|\.p12$|\.jks$|id_rsa$" | grep -v "node_modules\|test/" | sort -u)
if [[ -z "$key_history" ]]; then
  record "PASS" "P-49 No keys in history" "No private key files ever committed"
else
  tracked_keys=$(git -C "$SRC" ls-files 2>/dev/null | grep -E "\.pem$|\.key$|\.p12$|\.jks$|id_rsa$" | grep -v "node_modules\|test/")
  if [[ -n "$tracked_keys" ]]; then
    count=$(echo "$tracked_keys" | wc -l)
    record "FAIL" "P-49 Keys tracked" "$count key/cert files currently tracked in git (remove immediately)"
    echo "$tracked_keys" | head -5
  else
    count=$(echo "$key_history" | wc -l)
    record "PASS" "P-49 Keys removed" "$count key/cert files in git history but NOT currently tracked (.gitignore in place)"
  fi
fi
