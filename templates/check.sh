#!/bin/bash
###############################################################################
# Preston-Check — Community Check Template
#
# Copy this file into checks/community/proposed/ and rename it following the
# convention <NUMBER>-<short-name>.sh, where NUMBER is a unique ID in the
# 200-999 range (numbers below 200 are reserved for core checks).
#
# Example:
#   cp templates/check.sh checks/community/proposed/217-graphql-introspection.sh
#
# Fill in every required metadata field below. The PRESTON_META block is
# parsed by the runner; missing required fields cause the check to be
# rejected at load time.
###############################################################################

: <<'PRESTON_META'
schema_version: 1
id: P-XXX
name: Short title under 60 characters
description: One paragraph describing what the check catches and why it matters in a fintech / financial-services context.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.0.0
author_name: Your Name
author_github: yourhandle
author_org: optional-org-or-leave-blank
frameworks: PCI-DSS:4.0:6.5.1, SOC2:TSC-2017:CC6.1, OWASP-API:2023:API2
cwe: 798
owasp: API2:2023
nist_csf: PR.AC-1
false_positive_rate: low
performance_class: fast
origin: One-line narrative of where the pattern came from (incident, CVE, paper, etc.)
PRESTON_META

###############################################################################
# Field reference (delete this block before submission, or leave it for
# clarity — the parser ignores everything outside PRESTON_META markers):
#
# REQUIRED FIELDS
#   schema_version    Always 1 for the current schema
#   id                Unique identifier in the form P-XXX (community: 200-999)
#   name              Short human-readable title (under 60 chars)
#   description       One paragraph; explain what is caught and why it matters
#   category          code-scan | compliance-evidence | live-monitoring | infra-scan
#   severity          critical | high | medium | low | info
#   languages         "any" or comma-separated subset of:
#                     java, go, python, typescript, javascript, rust
#   min_tier          free | pro | enterprise (community contribs default to free)
#   runtime_class     static-grep (community contribs locked to static-grep)
#   evidence_required true if this check verifies compliance evidence; else false
#   version           semver of the check itself (start at 1.0.0)
#   added_in          Preston-Check version where this check was first introduced
#   author_name       Your name as shown in reports
#
# OPTIONAL FIELDS
#   author_github         Your GitHub handle (used for attribution in reports)
#   author_org            Your org or company
#   frameworks            Comma-separated Framework:Version:Control entries
#   cwe                   Comma-separated CWE numbers
#   owasp                 Comma-separated OWASP Top 10 references (e.g. API2:2023)
#   nist_csf              Comma-separated NIST CSF subcategories
#   false_positive_rate   low | medium | high (declared FPR)
#   performance_class     fast (<1s) | medium (<10s) | slow (<60s)
#   origin                Where this pattern came from (incident, CVE, etc.)
#   deprecated_in         Version where this check was deprecated
#   replaced_by           ID of replacement check (when deprecated)
###############################################################################

# The check body. The runner sources this file in its current shell and exposes
# the `record` function that takes (status, name, detail). Allowed status values:
# PASS, FAIL, WARN, SKIP. Use SOURCE_DIR for the source root.

echo "P-XXX: <Your check name>"

SRC="${SOURCE_DIR:-.}"

# Replace this stub with your detection logic. Stay within the static-grep
# runtime class — no network calls, no eval, no writes outside /tmp, no
# binaries beyond the shell built-ins and the standard text utilities
# (grep, find, awk, sed, cat, cut, sort, uniq, wc, head, tail, tr, xargs).

count=$(grep -rn --include="*.java" --include="*.ts" --include="*.js" --include="*.py" \
  -E "your_pattern_here" "$SRC" 2>/dev/null | wc -l | tr -d ' ')

if [[ ${count:-0} -eq 0 ]]; then
  record "PASS" "P-XXX <name>" "No issues found"
else
  record "FAIL" "P-XXX <name>" "$count occurrences of <pattern> detected"
fi
