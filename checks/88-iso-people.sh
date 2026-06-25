#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-88
name: ISO People Controls
description: Verifies screening, security training, offboarding, remote work policy.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: ISO-27001:2022:6.1, ISO-27001:2022:6.8, SOC2:TSC-2017:CC1.4
PRESTON_META


# P-88: ISO 27001 People Controls (A.6.x) Evidence
# Checks for screening, training, disciplinary, and termination procedure artifacts.
echo "P-88: ISO 27001 People Controls"
SRC="${SOURCE_DIR:-.}"

found=0

# A.6.1 — Screening (background checks)
screening=$(find "$SRC" -maxdepth 5 \( -iname "*background*check*" -o -iname "*screening*" -o -iname "*vetting*" -o -iname "*onboard*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$screening" ]] && found=$((found + 1))

# A.6.3 — Awareness/training
training=$(find "$SRC" -maxdepth 5 \( -iname "*training*" -o -iname "*awareness*" -o -iname "*security*education*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
training_ref=$(grep -rn --include="*.md" --include="*.yml" \
  "training.*program\|security.*awareness\|phishing.*simulation\|knowbe4\|annual.*training" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$training" || -n "$training_ref" ]] && found=$((found + 1))

# A.6.5 — Responsibilities after termination
termination=$(find "$SRC" -maxdepth 5 \( -iname "*offboard*" -o -iname "*termination*" -o -iname "*exit*procedure*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
term_code=$(grep -rn --include="*.java" --include="*.ts" \
  "deactivate.*user\|disable.*account\|revoke.*access\|offboard\|exit.*checklist" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -1)
[[ -n "$termination" || -n "$term_code" ]] && found=$((found + 1))

# A.6.7 — Remote working
remote=$(grep -rn --include="*.md" --include="*.yml" \
  "remote.*work\|work.*from.*home\|vpn.*policy\|remote.*access.*policy" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$remote" ]] && found=$((found + 1))

if [[ $found -ge 3 ]]; then
  record "PASS" "P-88 ISO people controls" "$found/4 people control evidence found"
elif [[ $found -ge 1 ]]; then
  record "WARN" "P-88 ISO people controls" "$found/4 — need: screening/onboarding, training, offboarding, remote work policy" "$(echo "$remote" | head -10)"
else
  record "WARN" "P-88 ISO people controls" "No people control evidence — create compliance/ directory with HR security procedures" "$(echo "$remote" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "deactivate.*user|disable.*account|revoke.*access|offboard|exit.*checklist" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-88 ISO People Controls (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-88 ISO People Controls (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "deactivate_user|disable_account|revoke_access|offboard|exit_checklist" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-88 ISO People Controls (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-88 ISO People Controls (Rust)" "No issues found in Rust files"
  fi
fi
