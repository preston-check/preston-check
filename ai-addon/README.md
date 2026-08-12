# Preston-Check AI add-on

Load Preston-Check into Claude, Llama, Kimi or any tool-calling LLM.
Two layers (design: `docs/ai-addon.md`):

The personas in `personas/` are auditor system prompts compiled from
the check catalog — they make a model behave as the tests behave, at a
chosen posture (strict / balanced / permissive) or through a compliance
lens (PCI-DSS, SOC2, ISO-27001, NIST-CSF, CIS-v8, OWASP). The MCP
server in `mcp/server.py` exposes the real scanner as tools, so the
model's findings are deterministic evidence, not recall. Use both
together: persona judges, scanner proves.

Everything is dependency-free: the server is stdlib Python, the
personas are plain text. `personas/` is generated — edit the catalog,
not these files, then regenerate with `python3 tools/build_personas.py`.

## Claude

Claude Code (CLI / desktop / IDE):

```bash
claude mcp add preston-check -- python3 /path/to/preston-check/ai-addon/mcp/server.py
```

Then paste a persona from `personas/claude/` as a custom agent's system
prompt (`.claude/agents/preston-strict.md`), into `CLAUDE.md`, or into a
claude.ai Project's custom instructions. Claude Desktop uses the same
server via `claude_desktop_config.json` (`command: python3`,
`args: [.../ai-addon/mcp/server.py]`).

## Llama (Ollama)

```bash
ollama create preston-strict -f personas/ollama/Modelfile.preston-strict
ollama run preston-strict "Audit this diff for hardcoded secrets: ..."
```

The Modelfiles default to `FROM llama3.1`; swap in any local tag
(`kimi-k2`, `mistral`, ...). MCP-capable Ollama front-ends can attach
`mcp/server.py` the same way as Claude.

## Kimi / OpenAI-compatible APIs

`personas/openai-compatible/<name>.json` carries `system` plus a
`tools` array of function definitions identical to the MCP tools:

```python
persona = json.load(open("personas/openai-compatible/preston-strict.json"))
resp = client.chat.completions.create(
    model="kimi-k2",  # or any tool-calling model
    messages=[{"role": "system", "content": persona["system"]}, ...],
    tools=persona["tools"],
)
```

Execute the returned tool calls against `mcp/server.py` (one JSON-RPC
line per call) or shell out to `preston-check.sh` directly.

## Tools

`scan_path(path, mode, severity?, framework?, category?,
include_proposed?)` — run the scanner, get scorecard + findings with
file:line evidence. `list_checks(...)` — browse catalog metadata,
paginated. `explain_check(check_id)` — one check's metadata plus its
actual detection source.

Scans always run `--airgap` (no network) and never modify the target.

## Verify an install

```bash
python3 ai-addon/mcp/server.py --selftest
```
