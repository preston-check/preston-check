#!/bin/bash
###############################################################################
# lib/branding.sh — White-label branding (Enterprise tier only)
#
# Free / Pro: report carries Preston-Check branding.
# Enterprise: customer can override BRAND_NAME, BRAND_LOGO_URL, BRAND_FOOTER,
# BRAND_COLOR via config keys. The override is silently ignored at non-Enterprise
# tiers (a note is printed to stderr).
###############################################################################

BRAND_NAME="Preston-Check"
BRAND_LOGO_URL=""
BRAND_FOOTER="Preston-Check Enterprise Security Suite"
BRAND_COLOR="#1a73e8"

apply_brand_config() {
  local config_file="${1:-$CONFIG_FILE}"
  [[ ! -f "$config_file" ]] && return 0

  local b_name b_logo b_footer b_color
  b_name=$(grep "^brand_name:" "$config_file" 2>/dev/null | cut -d: -f2- | xargs)
  b_logo=$(grep "^brand_logo_url:" "$config_file" 2>/dev/null | cut -d: -f2- | xargs)
  b_footer=$(grep "^brand_footer:" "$config_file" 2>/dev/null | cut -d: -f2- | xargs)
  b_color=$(grep "^brand_color:" "$config_file" 2>/dev/null | cut -d: -f2- | xargs)

  if [[ -n "$b_name" || -n "$b_logo" || -n "$b_footer" || -n "$b_color" ]]; then
    if [[ "${LICENSE_TIER:-free}" != "enterprise" ]]; then
      echo "  Note: brand_* config keys require Enterprise tier; ignoring." >&2
      return 0
    fi
    [[ -n "$b_name" ]] && BRAND_NAME="$b_name"
    [[ -n "$b_logo" ]] && BRAND_LOGO_URL="$b_logo"
    [[ -n "$b_footer" ]] && BRAND_FOOTER="$b_footer"
    [[ -n "$b_color" ]] && BRAND_COLOR="$b_color"
  fi
}

export -f apply_brand_config
