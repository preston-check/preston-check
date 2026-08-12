#!/bin/bash
###############################################################################
# install-ai-addon.sh — register the Preston-Check AI add-on with local hosts.
#
# Non-destructive by default: with no flags it detects what is installed and
# PRINTS the exact commands/config, touching nothing. Explicit flags act:
#   --claude          register the MCP server with Claude Code (claude mcp add)
#   --ollama [NAME]   create Ollama models (all personas, or just NAME)
#   --all             both of the above
# See MANUAL.md section 3-4 for the full walkthrough.
###############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Works from the package root (installer beside ai-addon/) or inside ai-addon/.
if [[ -f "$HERE/ai-addon/mcp/server.py" ]]; then ROOT="$HERE"; else ROOT="$(dirname "$HERE")"; fi
SERVER="$ROOT/ai-addon/mcp/server.py"
MODELFILES="$ROOT/ai-addon/personas/ollama"

DO_CLAUDE=false; DO_OLLAMA=false; OLLAMA_ONLY=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --claude) DO_CLAUDE=true; shift ;;
    --ollama) DO_OLLAMA=true; [[ "${2:-}" == preston-* || "${2:-}" == auditor-* ]] && { OLLAMA_ONLY="$2"; shift; }; shift ;;
    --all) DO_CLAUDE=true; DO_OLLAMA=true; shift ;;
    --help|-h) sed -n '3,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)"; exit 1 ;;
  esac
done

[[ -f "$SERVER" ]] || { echo "error: $SERVER not found — run from the extracted package"; exit 1; }
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
  echo "error: python3 >= 3.10 required"; exit 1
fi

echo "Preston-Check AI add-on @ $ROOT"
echo ""

if $DO_CLAUDE; then
  if command -v claude >/dev/null; then
    claude mcp add preston-check -- python3 "$SERVER" \
      && echo "registered with Claude Code (verify: claude mcp list)"
  else
    echo "error: claude CLI not found — install Claude Code first"; exit 1
  fi
elif command -v claude >/dev/null; then
  echo "Claude Code detected. To register (or re-run with --claude):"
  echo "  claude mcp add preston-check -- python3 $SERVER"
  echo ""
fi

if $DO_OLLAMA; then
  command -v ollama >/dev/null || { echo "error: ollama not found"; exit 1; }
  for mf in "$MODELFILES"/Modelfile.*; do
    name="${mf##*/Modelfile.}"
    [[ -n "$OLLAMA_ONLY" && "$name" != "$OLLAMA_ONLY" ]] && continue
    echo "creating ollama model: $name"
    ollama create "$name" -f "$mf" || exit 1
  done
elif command -v ollama >/dev/null; then
  echo "Ollama detected. To create the default auditor (or re-run with --ollama):"
  echo "  ollama create preston-balanced -f $MODELFILES/Modelfile.preston-balanced"
  echo ""
fi

cat <<EOF
Claude Desktop: add to claude_desktop_config.json ->
  {"mcpServers": {"preston-check": {"command": "python3", "args": ["$SERVER"]}}}

Kimi / OpenAI-compatible: system + tools JSON in
  $ROOT/ai-addon/personas/openai-compatible/

Verify the install:  python3 $SERVER --selftest
Full manual:         $ROOT/MANUAL.md
EOF
