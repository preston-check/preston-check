#!/bin/sh
###############################################################################
# Preston-Check installer
#
# Fetches the latest published Preston-Check release tarball from GitHub,
# verifies its SHA-256 against the .sha256 sidecar published alongside the
# release, and installs the runner into a target prefix on PATH.
#
# Usage (online):
#   curl -fsSL https://get.preston-check.com/install.sh | sh
#
# Usage (pin a version):
#   curl -fsSL https://get.preston-check.com/install.sh | PRESTON_VERSION=v1.7.1 sh
#
# Usage (custom install prefix):
#   curl -fsSL https://get.preston-check.com/install.sh | PRESTON_PREFIX=$HOME/.local sh
#
# Defaults:
#   PRESTON_VERSION   latest (resolved via /releases/latest)
#   PRESTON_PREFIX    /usr/local           (writable on macOS via Homebrew; sudo on Linux)
#   PRESTON_REPO      preston-check/preston-check
#
# This script is intentionally POSIX-sh and depends only on curl, tar, sha256
# and standard tools that ship with any modern Unix.
###############################################################################

set -eu

PRESTON_REPO="${PRESTON_REPO:-preston-check/preston-check}"
PRESTON_VERSION="${PRESTON_VERSION:-latest}"
PRESTON_PREFIX="${PRESTON_PREFIX:-/usr/local}"
RELEASE_BASE="https://github.com/${PRESTON_REPO}/releases"

err() { printf '\033[0;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
log() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"
}

require curl
require tar

if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CMD="shasum -a 256"
else
  err "missing sha256 tool (need sha256sum or shasum)"
fi

# Resolve the version string. "latest" → look up real tag from GitHub.
if [ "$PRESTON_VERSION" = "latest" ]; then
  log "Resolving latest release..."
  RESOLVED=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "${RELEASE_BASE}/latest" 2>/dev/null \
    | sed 's|.*/tag/||')
  [ -n "$RESOLVED" ] || err "could not resolve latest release"
  PRESTON_VERSION="$RESOLVED"
fi

# Strip leading 'v' if present, then re-add — accept both v1.7.1 and 1.7.1.
RAW="${PRESTON_VERSION#v}"
TAG="v${RAW}"

log "Installing Preston-Check ${TAG} into ${PRESTON_PREFIX}"

ARCHIVE="preston-check-${RAW}.tar.gz"
ARCHIVE_URL="${RELEASE_BASE}/download/${TAG}/${ARCHIVE}"
SHA_URL="${ARCHIVE_URL}.sha256"

# Stage in a temp dir; clean up no matter how we exit.
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t preston-check)
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"

log "Fetching archive..."
curl -fsSL -o "$ARCHIVE" "$ARCHIVE_URL" \
  || err "failed to download $ARCHIVE_URL"

log "Fetching checksum..."
curl -fsSL -o "${ARCHIVE}.sha256" "$SHA_URL" \
  || err "failed to download checksum"

EXPECTED=$(awk '{print $1}' "${ARCHIVE}.sha256")
ACTUAL=$($SHA256_CMD "$ARCHIVE" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  err "SHA-256 mismatch (expected $EXPECTED, got $ACTUAL) — refusing to install"
fi
log "Checksum verified."

log "Extracting..."
mkdir -p "$TMP/extract"
tar -xzf "$ARCHIVE" -C "$TMP/extract"

# The tarball top-level layout is the repo root. Locate preston-check.sh.
SH=$(find "$TMP/extract" -maxdepth 3 -name 'preston-check.sh' -type f | head -1)
[ -n "$SH" ] || err "preston-check.sh not found inside archive"
SOURCE_ROOT=$(dirname "$SH")

# Install layout:
#   $PREFIX/share/preston-check    — full repo (checks, lib, lang, modules)
#   $PREFIX/bin/preston-check      — thin shim that execs preston-check.sh
SHARE_DIR="$PRESTON_PREFIX/share/preston-check"
BIN_DIR="$PRESTON_PREFIX/bin"

if [ -d "$SHARE_DIR" ]; then
  log "Removing previous install at $SHARE_DIR"
  rm -rf "$SHARE_DIR"
fi
mkdir -p "$SHARE_DIR" "$BIN_DIR"

cp -R "$SOURCE_ROOT"/. "$SHARE_DIR"/
chmod +x "$SHARE_DIR/preston-check.sh"

cat > "$BIN_DIR/preston-check" <<EOF
#!/bin/sh
exec "$SHARE_DIR/preston-check.sh" "\$@"
EOF
chmod +x "$BIN_DIR/preston-check"

log "Installed:"
log "  $SHARE_DIR (catalog, lib, modules)"
log "  $BIN_DIR/preston-check (entrypoint)"

if ! command -v preston-check >/dev/null 2>&1; then
  cat <<EOF

Note: $BIN_DIR is not on your PATH. Add it to your shell rc:
  export PATH="$BIN_DIR:\$PATH"

Or invoke directly: $BIN_DIR/preston-check
EOF
fi

log "Done. Try: preston-check --version || preston-check --help"
