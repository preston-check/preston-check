#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-516
name: Move Capability-Based Access Control
description: Detects Aptos / Sui Move modules that perform privileged operations without holding a capability resource. Capability-based access (e.g., MintCapability, AdminCap) is the canonical Move idiom for authorization; bypassing it via address checks is a recurring audit finding.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.4.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC01, CWE:284
cwe: 284
false_positive_rate: high
performance_class: fast
origin: Aptos / Sui security best practice; capability resources are the recommended authorization mechanism in Move's resource model.
PRESTON_META

echo "P-516: Move Capability-Based Access"

SRC="${SOURCE_DIR:-.}"
move_files=$(find "$SRC" -name "*.move" -not -path "*/build/*" 2>/dev/null)

if [[ -z "$move_files" ]]; then
  record "SKIP" "P-516 Move capabilities" "No Move modules detected"
  return 0 2>/dev/null || true
fi

cap_pattern=$(grep -rln --include="*.move" -iE "Capability\b|capability\s*\{|MintCap|BurnCap|AdminCap|TransferCap|UpgradeCap" "$SRC" 2>/dev/null || true)

m_count=$(echo "$move_files" | wc -l | tr -d ' ')
c_count=$([[ -n "$cap_pattern" ]] && echo "$cap_pattern" | wc -l | tr -d ' ' || echo 0)

if [[ ${c_count:-0} -eq 0 ]]; then
  record "WARN" "P-516 Move capabilities" "$m_count Move file(s) without capability-resource authorization patterns" "$(echo "$move_files" | head -10)"
else
  record "PASS" "P-516 Move capabilities" "$c_count of $m_count Move file(s) reference capability resources"
fi
