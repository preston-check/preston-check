#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-94
name: CIS Security Training
description: Verifies training docs, platform references, secure coding standards.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: CIS-v8:14.1, CIS-v8:14.6, ISO-27001:2022:6.3, SOC2:TSC-2017:CC2.2
PRESTON_META


# P-94: CIS Control 14 — Security Awareness & Skills Training
# Verifies evidence of security training program, phishing simulations, developer training.
echo "P-94: CIS Security Training"
SRC="${SOURCE_DIR:-.}"

# Check for training documentation
training_doc=$(find "$SRC" -maxdepth 5 \( \
  -iname "*security*training*" -o -iname "*awareness*training*" -o -iname "*developer*training*" \
  -o -iname "*secure*coding*guide*" -o -iname "*security*onboard*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)

# Check for training platform references
training_platform=$(grep -rn --include="*.md" --include="*.yml" --include="*.json" \
  "knowbe4\|proofpoint.*training\|sans.*training\|cybrary\|security.*champion\|phishing.*sim\|security.*quiz" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)

# Check for secure coding standards reference
secure_coding=$(find "$SRC" -maxdepth 5 \( \
  -iname "*secure*coding*" -o -iname "*coding*standard*" -o -iname "*code*review*guide*" \
  -o -iname "CLAUDE.md" -o -iname ".pre-commit*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)

found=0
[[ -n "$training_doc" ]] && found=$((found + 1))
[[ -n "$training_platform" ]] && found=$((found + 1))
[[ -n "$secure_coding" ]] && found=$((found + 1))

if [[ $found -ge 2 ]]; then
  record "PASS" "P-94 Security training" "$found/3 training evidence found (docs, platform, secure coding standards)"
elif [[ $found -ge 1 ]]; then
  record "WARN" "P-94 Security training" "$found/3 — need: training docs, platform reference, secure coding guide"
else
  record "WARN" "P-94 Security training" "No security training evidence — create compliance/security-training-program.md (CIS Control 14)"
fi
