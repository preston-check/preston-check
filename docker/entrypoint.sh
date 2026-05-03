#!/bin/bash
###############################################################################
# docker/entrypoint.sh — optional wrapper for Docker invocations
#
# The Dockerfile invokes preston-check.sh directly. This wrapper exists for
# users who want CI-style behavior (license file from secret, telemetry
# disabled by default, friendlier error messages).
###############################################################################

set -uo pipefail

# Honor PRESTON_LICENSE_CONTENT env var as an inline license (for CI secrets)
if [[ -n "${PRESTON_LICENSE_CONTENT:-}" ]]; then
  mkdir -p /home/preston/.preston-check
  printf '%s' "$PRESTON_LICENSE_CONTENT" > /home/preston/.preston-check/license
fi

exec /opt/preston-check/preston-check.sh "$@"
