#!/bin/bash
###############################################################################
# lib/oss_detection.sh — Auto-grant Pro features for OSS repositories
#
# If the source_dir contains a recognized OSS LICENSE file (MIT, Apache, BSD,
# GPL, MPL, ISC, Unlicense), the tool grants Pro-tier features for free. This
# is a deliberate viral lever: it captures the GitHub developer marketplace,
# every public repo running Preston-Check is free marketing, and fintech devs
# who already trust the tool from their OSS work are the natural buyers when
# they hit a SOC 2 deadline at their day job.
###############################################################################

OSS_DETECTED="false"
OSS_LICENSE_TYPE=""

detect_oss_license() {
  local src="${1:-${SOURCE_DIR:-.}}"
  OSS_DETECTED="false"
  OSS_LICENSE_TYPE=""

  local license_file=""
  for candidate in LICENSE LICENSE.md LICENSE.txt COPYING COPYING.md license license.md; do
    if [[ -f "$src/$candidate" ]]; then
      license_file="$src/$candidate"
      break
    fi
  done

  [[ -z "$license_file" ]] && return 0

  local content
  content=$(head -250 "$license_file" 2>/dev/null)

  # Order matters: more specific patterns come first to avoid mis-detection
  # (e.g. AGPL/LGPL matched before generic GPL).
  if echo "$content" | grep -qiE "Apache License|Licensed under the Apache License"; then
    OSS_LICENSE_TYPE="Apache-2.0"
    OSS_DETECTED="true"
  elif echo "$content" | grep -qiE "MIT License|Permission is hereby granted, free of charge"; then
    OSS_LICENSE_TYPE="MIT"
    OSS_DETECTED="true"
  elif echo "$content" | grep -qiE "BSD.*License|Redistribution and use in source and binary forms"; then
    OSS_LICENSE_TYPE="BSD"
    OSS_DETECTED="true"
  elif echo "$content" | grep -qiE "GNU GENERAL PUBLIC LICENSE|GNU LESSER GENERAL PUBLIC LICENSE|GNU AFFERO GENERAL PUBLIC LICENSE"; then
    OSS_LICENSE_TYPE="GPL"
    OSS_DETECTED="true"
  elif echo "$content" | grep -qiE "Mozilla Public License"; then
    OSS_LICENSE_TYPE="MPL"
    OSS_DETECTED="true"
  elif echo "$content" | grep -qiE "ISC License|Permission to use, copy, modify, and/or distribute"; then
    OSS_LICENSE_TYPE="ISC"
    OSS_DETECTED="true"
  elif echo "$content" | grep -qiE "This is free and unencumbered software released into the public domain"; then
    OSS_LICENSE_TYPE="Unlicense"
    OSS_DETECTED="true"
  fi
}

# Effective tier accounts for OSS exemption. If the repo is OSS and the user
# is on the free tier (or has no license), they get Pro features.
effective_tier() {
  local base_tier="${1:-${LICENSE_TIER:-free}}"
  if [[ "$OSS_DETECTED" == "true" ]] && [[ "$base_tier" == "free" ]]; then
    echo "pro"
    return 0
  fi
  echo "$base_tier"
}

print_oss_status() {
  if [[ "$OSS_DETECTED" == "true" ]]; then
    echo "  OSS: detected ($OSS_LICENSE_TYPE) — Pro features granted free for this repo"
  fi
}

export -f detect_oss_license effective_tier print_oss_status
