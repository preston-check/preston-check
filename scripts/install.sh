#!/bin/bash
###############################################################################
# Preston-Check installer
#
#   curl -fsSL https://get.preston-check.dev/install.sh | sh
#
# Flags:
#   --prefix DIR    Install to DIR instead of $HOME/.preston-check/install
#   --version VER   Install a specific version (default: latest)
#   --no-symlink    Do not create the /usr/local/bin/preston-check symlink
###############################################################################

set -euo pipefail

PREFIX="${PREFIX:-${HOME}/.preston-check/install}"
VERSION="${VERSION:-latest}"
SYMLINK="true"
GH_REPO="${PRESTON_REPO:-preston-check/preston-check}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)     PREFIX="$2"; shift 2 ;;
    --version)    VERSION="$2"; shift 2 ;;
    --no-symlink) SYMLINK="false"; shift ;;
    --help|-h)
      sed -n '2,/^####/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

for cmd in curl tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: $cmd is required but not found on PATH." >&2
    exit 1
  fi
done

echo "Installing Preston-Check $VERSION to $PREFIX..."

mkdir -p "$PREFIX"

if [[ "$VERSION" == "latest" ]]; then
  TARBALL_URL="https://github.com/${GH_REPO}/releases/latest/download/preston-check.tar.gz"
else
  TARBALL_URL="https://github.com/${GH_REPO}/releases/download/${VERSION}/preston-check.tar.gz"
fi

TMP_TARBALL=$(mktemp /tmp/preston-check.XXXXXX.tar.gz)
trap 'rm -f "$TMP_TARBALL"' EXIT

if ! curl -fsSL "$TARBALL_URL" -o "$TMP_TARBALL"; then
  echo "ERROR: failed to download $TARBALL_URL" >&2
  echo "Falling back to git clone..." >&2
  if command -v git >/dev/null 2>&1; then
    rm -rf "$PREFIX/.tmp-clone"
    git clone --depth 1 "https://github.com/${GH_REPO}.git" "$PREFIX/.tmp-clone"
    cp -r "$PREFIX/.tmp-clone"/* "$PREFIX/"
    rm -rf "$PREFIX/.tmp-clone"
  else
    echo "ERROR: git not available either; cannot install." >&2
    exit 1
  fi
else
  tar -xzf "$TMP_TARBALL" -C "$PREFIX" --strip-components=1
fi

chmod +x "$PREFIX/preston-check.sh" \
         "$PREFIX/checks"/*.sh \
         "$PREFIX/tools"/*.sh 2>/dev/null || true

# Symlink for convenience
if [[ "$SYMLINK" == "true" ]]; then
  if [[ -w /usr/local/bin || $(id -u) -eq 0 ]]; then
    ln -sf "$PREFIX/preston-check.sh" /usr/local/bin/preston-check
    echo "Symlinked /usr/local/bin/preston-check"
  else
    echo "Note: not symlinking (no write access to /usr/local/bin)."
    echo "Add to your PATH or run with $PREFIX/preston-check.sh"
  fi
fi

echo ""
echo "Preston-Check installed successfully."
echo ""
echo "Quick start:"
echo "  $PREFIX/preston-check.sh --help"
echo ""
echo "Free tier runs immediately. For Pro/Enterprise, install your license at:"
echo "  ~/.preston-check/license"
echo ""
echo "Docs:    https://preston-check.dev"
echo "Source:  https://github.com/${GH_REPO}"
