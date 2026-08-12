# Preston-Check AI Add-on — Owner's Manual

This manual covers installing, using, and maintaining the Preston-Check
AI add-on: the package that loads Preston-Check into Claude, Llama,
Kimi, and any other tool-calling language model. It assumes no prior
knowledge of the Preston-Check internals. If you only want the
five-minute version, read Quick Start and stop.

## 1. What this package is

Preston-Check is a deterministic pre-deployment security scanner: a
catalog of shell-based checks, hand-curated and auto-evolved daily from
live threat intelligence, each carrying structured metadata (severity,
CWE, compliance-framework mappings) and shipping with signed
attestations. This add-on makes that catalog loadable into an AI
assistant through two cooperating layers.

The persona layer is a set of auditor system prompts compiled directly
from the check catalog. A persona teaches the model to behave as the
tests behave: what to look for, at which severity, with which
temperament. Load a persona into any model — even one with no tool
support — and it audits code in Preston's vocabulary, honestly
labelling its findings as model judgment.

The evidence layer is an MCP (Model Context Protocol) server that
exposes the real scanner as callable tools. When a model has these
tools, the persona instructs it to treat scanner output as ground
truth: it runs the deterministic checks first, then applies judgment to
triage, explain, and propose fixes. Persona judges; scanner proves.

What this package deliberately is not: a fine-tuned model. Weights
would freeze a catalog that changes daily, reintroduce hallucinated
findings, and cannot produce attestations.

## 2. Package contents

```
preston-check-ai-addon-<version>/
├── MANUAL.md / MANUAL.pdf      this document
├── install-ai-addon.sh         guided installer (non-destructive by default)
├── VERSION                     package version stamp
├── preston-check.sh            the scanner CLI
├── checks/                     the full check catalog
├── lib/  lang/  config.yml     scanner support files
├── LICENSE  NOTICE
└── ai-addon/
    ├── mcp/server.py           MCP server (Python 3.10+, stdlib only)
    └── personas/
        ├── claude/*.md         system prompts
        ├── ollama/Modelfile.*  Ollama model definitions
        └── openai-compatible/*.json   system + tools JSON
```

Requirements: Python 3.10 or newer and bash. Nothing is downloaded and
no Python packages are installed — the server is standard library only.
The scanner never modifies scanned code, and all add-on scans run with
`--airgap` (no network calls, no telemetry).

## 3. Quick start

Extract the package anywhere permanent (the install registers absolute
paths), then run the installer to see exactly what applies to your
machine:

```bash
tar xzf preston-check-ai-addon-<version>.tar.gz
cd preston-check-ai-addon-<version>
./install-ai-addon.sh            # prints instructions for detected hosts
./install-ai-addon.sh --claude   # actually registers with Claude Code
./install-ai-addon.sh --ollama   # actually creates Ollama models
python3 ai-addon/mcp/server.py --selftest   # verify: expect "selftest PASS"
```

## 4. Loading into each host

### 4.1 Claude Code (CLI, desktop app, IDE extensions)

Register the MCP server once:

```bash
claude mcp add preston-check -- python3 /abs/path/to/ai-addon/mcp/server.py
```

Claude immediately gains the three tools (section 6). To add a persona,
create a custom agent whose system prompt is one of the files in
`ai-addon/personas/claude/` — for example copy
`personas/claude/preston-strict.md` to
`.claude/agents/preston-strict.md` in your project and ask Claude to
"use the preston-strict agent to audit this repo". Lighter-touch
alternative: paste the persona into your project's `CLAUDE.md`.

### 4.2 Claude Desktop (chat app)

Add the server to `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/`):

```json
{
  "mcpServers": {
    "preston-check": {
      "command": "python3",
      "args": ["/abs/path/to/ai-addon/mcp/server.py"]
    }
  }
}
```

Restart the app; the tools appear in the connector menu. Paste a
persona into a Project's custom instructions to complete the pairing.

### 4.3 claude.ai (web, no local process)

The web app cannot spawn a local MCP server, so use the persona layer
alone: create a Project and paste a `personas/claude/*.md` file into
its custom instructions. The persona detects that tools are absent and
labels findings as model judgment. Paste the code to audit into the
conversation.

### 4.4 Llama and other local models (Ollama)

Each Modelfile wraps a persona around a base model:

```bash
ollama create preston-strict -f ai-addon/personas/ollama/Modelfile.preston-strict
ollama run preston-strict "Audit the following diff: ..."
```

The Modelfiles default to `FROM llama3.1` with `num_ctx 49152` (the
largest persona is roughly 26k tokens — do not shrink the context below
that or the catalog gets truncated silently). Swap the FROM line for
any local tag: `kimi-k2`, `qwen2.5-coder`, `mistral`, etc. MCP-capable
Ollama front-ends (LM Studio, Open WebUI and similar) can additionally
attach `mcp/server.py` exactly as Claude Desktop does.

### 4.5 Kimi (Moonshot API) and any OpenAI-compatible endpoint

The JSON personas carry the system prompt plus function-calling tool
definitions that mirror the MCP tools one-to-one:

```python
import json, subprocess
from openai import OpenAI

persona = json.load(open("ai-addon/personas/openai-compatible/preston-strict.json"))
client = OpenAI(base_url="https://api.moonshot.ai/v1", api_key=KEY)

messages = [{"role": "system", "content": persona["system"]},
            {"role": "user", "content": "Audit /path/to/repo"}]
resp = client.chat.completions.create(
    model="kimi-k2", messages=messages, tools=persona["tools"])
```

When the model returns a `tool_call`, execute it against the MCP server
(one JSON-RPC line in, one out) or translate it to the CLI directly
(`scan_path` maps to `preston-check.sh --ci-soft --airgap ...`), append
the result as a `tool` message, and continue the loop. The same JSON
works for vLLM, LM Studio's server mode, llama.cpp's server, and
OpenAI's own models.

## 5. The personas

Eleven personas ship in every format. Counts are from catalog v1.8.x
and grow as the catalog evolves.

| Persona | Checks | Use when |
|---|---|---|
| preston-strict | ~488 | Pre-release audits, security reviews; false positives acceptable |
| preston-balanced | ~509 | Day-to-day PR review; the sensible default |
| preston-permissive | ~466 | Noisy legacy codebases; only unambiguous findings |
| auditor-pci-dss | ~103 | Payment-card scope; findings cite PCI-DSS controls |
| auditor-soc2 | ~102 | SOC 2 readiness; findings cite TSC criteria |
| auditor-iso-27001 | ~145 | ISO 27001 audits; findings cite Annex A controls |
| auditor-nist-csf | ~191 | NIST CSF alignment reviews |
| auditor-cis-v8 | ~82 | CIS Controls v8 assessments |
| auditor-owasp-api | ~42 | API security reviews |
| auditor-owasp-top-10 | ~22 | Classic web-app top-10 reviews |
| auditor-owasp-sc-top-10 | ~27 | Smart-contract reviews |

The three postures mirror the catalog's own variant system — every
threat-intel CVE ships as strict, middle, and permissive detection
variants, and each posture persona embeds the matching variant set plus
the entire core catalog. Compliance personas scope the model to checks
mapped to that framework and instruct it to cite the mapped control IDs
in findings.

Every persona enforces the same behavioral contract: findings are
reported in the runner's vocabulary (PASS / FAIL / WARN / SKIP),
ordered by severity, with file:line evidence; CVE identifiers and line
numbers are never fabricated; uncertainty downgrades a finding to WARN
with a stated reason; unverified early-warning material is labelled
`[UNVERIFIED]`; and every audit ends with a scorecard and a remediation
plan.

## 6. Tool reference

### scan_path

Runs the real scanner against a directory and returns evidence.

| Parameter | Type | Notes |
|---|---|---|
| path | string, required | Directory to scan; `~` is expanded |
| mode | `light` or `full` | light = core P-01..P-20, ~30 s (default); full = entire catalog, ~3 min |
| severity | string | Comma-separated filter: `critical,high,medium,low,info` |
| framework | string | Only checks referencing this framework (e.g. `PCI-DSS`, `MiCA`) |
| category | string | `code-scan`, `compliance-evidence`, `infra-scan`, `live-monitoring` |
| include_proposed | boolean | Also run unverified early-warning checks; findings labelled `[UNVERIFIED]` |

Returns a text block (summary, findings with file:line evidence, full
markdown report — truncated at 40 kB with an explicit notice) plus
structured counts (`PASS`, `FAIL`, `WARN`, `SKIP`, `total`). Timeouts:
180 s light, 600 s full; a timeout returns an error result rather than
hanging the host.

### list_checks

Browses catalog metadata. Parameters: `tier` (`core`, `verified`,
`accepted`, `all`), `severity`, `framework_contains` (substring match),
`limit` (default 50, max 200), `offset`. The result always reports
`total`, so pagination is explicit and nothing is silently capped.

### explain_check

Takes a `check_id` (`P-01`, `P-1157`, ...) and returns the check's full
metadata plus its actual detection source code — explanations of what a
test does are grounded in the script, never in model recall.

## 7. Recipes

Audit a repository (Claude Code with the server registered): "Scan
~/work/api-server with preston-check, full mode, high-and-up severity,
then explain the top three findings and propose minimal fixes." The
model calls `scan_path`, reads the evidence, and uses `explain_check`
for the checks it discusses.

Compliance snapshot: load `auditor-pci-dss` and ask "What is our
PCI-DSS posture?" — the persona scopes the scan with
`framework: PCI-DSS` and reports findings against control IDs.

Local pre-commit review without cloud calls: `git diff | ollama run
preston-balanced "Audit this diff"`. This is persona-only judgment;
follow up with the CLI (`./preston-check.sh --ci`) for scanner
evidence.

Early-warning sweep: ask for a scan with `include_proposed: true` to
include detections synthesized from uncorroborated intel sources.
Treat `[UNVERIFIED]` findings as leads, not conclusions.

## 8. Troubleshooting

Server does not appear in the host: confirm `python3 --version` is
3.10+, run the selftest, and check the host's MCP log (Claude Code:
`claude mcp list`). The server path in the registration must be
absolute.

`scan_path` returns "scanner produced no check results": the target
path is wrong or unreadable, or bash is unavailable. The error includes
the scanner's stdout/stderr tail — read it; it names the cause.

Scans time out in full mode on huge monorepos: scope with `severity`
or `category`, or scan a subdirectory.

Ollama output ignores most of the catalog: the base model's context is
too small. Keep `num_ctx` at 49152 or higher, or use a compliance
persona (they are much smaller than the postures).

A persona claims a finding the scanner does not report: that is model
judgment overreach — the behavioral contract tells the model to defer
to scanner evidence, so re-ask with "run scan_path and reconcile". If
it persists, the model is too weak to honor the contract; use a
stronger model or rely on the CLI.

Findings reference `[UNVERIFIED]`: those come from the proposed tier
(only when `include_proposed` was requested) and are early warnings
from uncorroborated sources, deliberately excluded from persona
knowledge and default scans.

## 9. Security and privacy

Scans are read-only and airgapped: the add-on invokes the scanner with
`--airgap`, which disables telemetry and all network calls. The MCP
server binds no ports — it is a child process of the host speaking
JSON-RPC over stdio, alive only while the host runs. It installs no
dependencies. Scanned code never leaves the machine through this
package; whatever the *model host* does with conversation content is
governed by that host's own policies, so pair local models (Ollama)
with sensitive codebases when in doubt.

## 10. Updating and regenerating

The catalog evolves daily; personas are compiled artifacts and go stale
gently (an outdated persona still audits, it just lacks the newest
checks — scanner tools always reflect the installed catalog). To
refresh, download a newer package, or from a git checkout run:

```bash
python3 tools/build_personas.py       # regenerate personas from the catalog
python3 tools/build_ai_addon_package.py   # rebuild this package into dist/
```

Regeneration is deterministic: identical catalog in, identical bytes
out. Never hand-edit `personas/` — the generator is its single writer
and will overwrite you.

## 11. FAQ

Why not a fine-tuned model? Frozen weights versus a daily-evolving
catalog, hallucinated findings versus deterministic evidence, and no
attestations. The persona-plus-tools split gets current knowledge and
provable findings on any host model, including ones (like Claude) that
do not accept custom weights at all.

Can I use only the personas, without the server? Yes — that is the
claude.ai and plain-Ollama path. You get Preston's judgment and
vocabulary with clearly-labelled model findings, and you can always
verify with the CLI.

Can I use only the server, without a persona? Yes — any MCP host gains
the three tools and can scan on demand. You lose the auditor behavior:
report structure, severity discipline, and the defer-to-evidence
contract.

Which persona should I start with? `preston-balanced` everywhere,
`preston-strict` before releases.

Does this replace running preston-check in CI? No. CI remains the
deterministic gate (`--ci` exits 1 on FAIL). The add-on is the
interactive layer for reviews, triage, and explanation.

License: the same terms as the Preston-Check distribution it is built
from — see LICENSE and NOTICE in the package root.
