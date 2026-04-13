#!/bin/bash
# P-59: Security Policy Documentation — PCI-DSS 12.1, SOC 2 CC1.1, ISO 27001 A.5.1
# Verifies existence of required security policy documents.
echo "P-59: Security Policy Documentation"
SRC="${SOURCE_DIR:-.}"

required_docs=0
found_docs=0

# Check for incident response plan
ir_plan=$(find "$SRC" -maxdepth 4 -iname "*incident*response*" -o -iname "*ir-plan*" -o -iname "*incident*plan*" 2>/dev/null | head -1)
required_docs=$((required_docs + 1))
if [[ -n "$ir_plan" ]]; then
  found_docs=$((found_docs + 1))
fi

# Check for disaster recovery plan
dr_plan=$(find "$SRC" -maxdepth 4 -iname "*disaster*recovery*" -o -iname "*dr-plan*" -o -iname "*business*continuity*" 2>/dev/null | head -1)
required_docs=$((required_docs + 1))
if [[ -n "$dr_plan" ]]; then
  found_docs=$((found_docs + 1))
fi

# Check for security policy
sec_policy=$(find "$SRC" -maxdepth 4 -iname "*security*policy*" -o -iname "*infosec*policy*" 2>/dev/null | head -1)
required_docs=$((required_docs + 1))
if [[ -n "$sec_policy" ]]; then
  found_docs=$((found_docs + 1))
fi

# Check for deployment/change management docs
deploy_doc=$(find "$SRC" -maxdepth 4 -iname "*deploy*guide*" -o -iname "*change*management*" -o -iname "*runbook*" 2>/dev/null | head -1)
required_docs=$((required_docs + 1))
if [[ -n "$deploy_doc" ]]; then
  found_docs=$((found_docs + 1))
fi

# Check for data classification
data_class=$(find "$SRC" -maxdepth 4 -iname "*data*classification*" -o -iname "*data*handling*" 2>/dev/null | head -1)
required_docs=$((required_docs + 1))
if [[ -n "$data_class" ]]; then
  found_docs=$((found_docs + 1))
fi

if [[ $found_docs -ge 4 ]]; then
  record "PASS" "P-59 Policy documentation" "$found_docs/$required_docs required security documents found"
elif [[ $found_docs -ge 2 ]]; then
  record "WARN" "P-59 Policy documentation" "$found_docs/$required_docs required security documents found"
else
  record "WARN" "P-59 Policy documentation" "Only $found_docs/$required_docs required security documents found (need IR plan, DR plan, security policy, deploy guide, data classification)"
fi
