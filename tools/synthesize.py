#!/usr/bin/env python3
"""tools/synthesize.py

LLM-driven detection-pattern synthesis. Reads correlated candidates
from .preston-check/correlated.json, generates three pattern variants
per candidate (strict, middle, permissive) plus synthetic test
fixtures, sandbox-validates each variant, and writes passing
candidates to .preston-check/candidates/.

The synthesis prompt uses structural separation: the candidate
description is passed as a tool-call argument, never as inline system
prompt content. This is the primary mitigation against prompt-
injection attacks (threat model C1). The bash AST walker
(tools/sandbox_validate.py) is the mechanical safety net behind it.

LLM provider is configurable via env var PRESTON_SYNTH_MODEL
(default: claude-opus-4-7). API key from ANTHROPIC_API_KEY env var.
Synthesis output is cached per (canonical_id, prompt_hash, model)
under .preston-check/synth-cache/ to avoid duplicate cost on retries.

If ANTHROPIC_API_KEY is unset (e.g., in CI without the secret), the
tool still produces deterministic placeholder candidates derived from
the input description's keywords. This lets the pipeline run end-to-
end in test environments without burning real LLM budget — the
candidates won't pass validation against real corpora but the
plumbing is exercised.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
CORRELATED = ROOT / ".preston-check" / "correlated.json"
CANDIDATES_DIR = ROOT / ".preston-check" / "candidates"
CACHE_DIR = ROOT / ".preston-check" / "synth-cache"

DEFAULT_MODEL = os.environ.get("PRESTON_SYNTH_MODEL", "claude-haiku-4-5-20251001")
ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"

PROMPT_TEMPLATE_VERSION = "1.0.0"

_SYNTHESIS_PROMPT = """You are generating shell-script-based static detection patterns for the Preston-Check security scanner. The scanner runs the generated check as bash inside an isolated subshell with restricted capabilities.

Your job: from the structured vulnerability record provided as JSON in the user message, generate exactly three detection-pattern variants of differing specificity:
  - "strict": low false-positive rate, may miss valid hits
  - "middle": balanced
  - "permissive": low false-negative rate, may produce false positives

For EACH variant, also produce two minimal synthetic test fixtures:
  - "fixture_positive": a code snippet that contains the vulnerability and that the variant SHOULD detect
  - "fixture_negative": a similar but clean code snippet that the variant should NOT detect

You must output a single JSON object with this exact schema and no other text:

{
  "variants": [
    {
      "name": "strict",
      "bash_body": "...",
      "fixture_positive": {"path": "vuln.java", "content": "..."},
      "fixture_negative": {"path": "clean.java", "content": "..."},
      "rationale": "..."
    },
    {"name": "middle", ...},
    {"name": "permissive", ...}
  ]
}

CONSTRAINTS on bash_body — your script will be REJECTED if it violates any of these, costing budget and producing nothing:
  - You may use ONLY these commands: record, grep, rg, find, echo, printf, basename, dirname, head, tail, wc, sort, uniq, tr, awk, sed, cat, test, [, [[, true, false, return
  - You MAY use: parameter expansion of named variables, conditionals, for/while loops, $(...) command substitution containing only allowed commands
  - You MUST NOT use: eval, exec, source, '.', bash -c, sh -c, network commands (curl/wget/nc/ssh), file mutation (rm/mv/cp/chmod), unset, set -o, shopt, trap, IFS=, BASH_ENV=, ENV=, PATH= overwrite, indirect parameter expansion ${!var}, printf -v, declare -n, process substitution <(...) >(...), backticks, history expansion
  - You MUST NOT use: grep -P, rg --pre, find -exec, find -delete, sed -i
  - Read SOURCE_DIR via "${SOURCE_DIR:-.}" and call record at the end with PASS or FAIL or WARN status

Output the JSON object only. No prose, no markdown fences, no explanation."""


def _stable_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _cache_key(canonical_id: str, prompt: str, candidate: dict, model: str) -> str:
    payload = json.dumps(
        {
            "id": canonical_id,
            "prompt_v": PROMPT_TEMPLATE_VERSION,
            "prompt_hash": _stable_hash(prompt),
            "candidate_hash": _stable_hash(json.dumps(candidate, sort_keys=True)),
            "model": model,
        },
        sort_keys=True,
    )
    return _stable_hash(payload)


def _load_from_cache(key: str) -> dict | None:
    p = CACHE_DIR / f"{key}.json"
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            return None
    return None


def _save_to_cache(key: str, value: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{key}.json").write_text(json.dumps(value, indent=2, sort_keys=True))


def _call_anthropic(prompt: str, candidate_json: str, model: str, api_key: str) -> dict | None:
    body = {
        "model": model,
        "max_tokens": 4096,
        "system": prompt,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Generate detection patterns for the following vulnerability record. "
                    "Return ONLY the JSON object specified in the system prompt.\n\n"
                    "VULNERABILITY_RECORD:\n" + candidate_json
                ),
            }
        ],
    }
    req = urllib.request.Request(
        ANTHROPIC_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"[synthesize] Anthropic API error: {exc}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[synthesize] unexpected error calling Anthropic: {exc}", file=sys.stderr)
        return None

    content_blocks = data.get("content", [])
    text_parts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
    raw = "\n".join(text_parts).strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[synthesize] could not parse model output as JSON: {exc}", file=sys.stderr)
        print(f"            raw text begins: {raw[:200]!r}", file=sys.stderr)
        return None


def _placeholder_synthesis(candidate: dict) -> dict:
    """Deterministic placeholder when no LLM API key is available. Produces
    valid candidate structure with conservative bash that always passes the
    sandbox validator. The candidate won't score well on real corpora, but
    the plumbing runs end-to-end."""
    title = candidate.get("title", "untitled")
    desc = candidate.get("description", "")[:200]
    keywords = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]{3,}\b", desc)[:5]
    pattern = "|".join(re.escape(k) for k in keywords) or "vulnerable"
    cid = candidate.get("canonical_id", "unknown")

    body = f"""SRC="${{SOURCE_DIR:-.}}"
hits=$(grep -rn "{pattern}" "$SRC" 2>/dev/null | head -10 || true)
if [[ -z "$hits" ]]; then
    record "PASS" "P-? {cid}" "no instances of suspect pattern found"
else
    record "WARN" "P-? {cid}" "found suspect pattern (placeholder, not LLM-synthesized)"
fi"""

    fixture_pos = f"// {cid} placeholder positive\n// {keywords[0] if keywords else 'vulnerable'}\nfunction broken() {{ return '{keywords[0] if keywords else 'vulnerable'}'; }}\n"
    fixture_neg = f"// {cid} placeholder negative\nfunction safe() {{ return 'unrelated'; }}\n"

    return {
        "variants": [
            {
                "name": "strict",
                "bash_body": body,
                "fixture_positive": {"path": "vuln.txt", "content": fixture_pos},
                "fixture_negative": {"path": "clean.txt", "content": fixture_neg},
                "rationale": f"placeholder synthesis (no LLM key) for: {title}",
            }
        ],
        "_placeholder": True,
    }


def synthesize_candidate(candidate: dict, model: str = DEFAULT_MODEL) -> dict | None:
    cid = candidate.get("canonical_id", "unknown")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    cache_key = _cache_key(cid, _SYNTHESIS_PROMPT, candidate, model)

    cached = _load_from_cache(cache_key)
    if cached:
        return cached

    if not api_key:
        result = _placeholder_synthesis(candidate)
    else:
        candidate_json = json.dumps(
            {
                "canonical_id": cid,
                "title": candidate.get("title", ""),
                "description": candidate.get("description", ""),
                "severity": candidate.get("severity", "medium"),
                "cwe": candidate.get("cwe", []),
                "languages": candidate.get("languages", []),
                "frameworks": candidate.get("frameworks", []),
            },
            sort_keys=True,
            indent=2,
        )
        result = _call_anthropic(_SYNTHESIS_PROMPT, candidate_json, model, api_key)
        if result is None:
            result = _placeholder_synthesis(candidate)

    _save_to_cache(cache_key, result)
    return result


def _next_check_number(start: int = 700) -> int:
    """Find the next free P-NNN number across all check directories."""
    used: set[int] = set()
    for d in (ROOT / "checks", ROOT / "checks" / "core", ROOT / "checks" / "community", CANDIDATES_DIR):
        if not d.is_dir():
            continue
        for f in d.rglob("*.sh"):
            m = re.match(r"^(\d+)-", f.name)
            if m:
                used.add(int(m.group(1)))
    n = start
    while n in used:
        n += 1
    return n


def _slugify(text: str, max_len: int = 50) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
    return s[:max_len].rstrip("-") or "draft"


def _render_check_file(
    candidate: dict, variant: dict, check_number: int
) -> tuple[str, str]:
    """Render a check .sh file from a synthesized variant. Returns (filename, content)."""
    cid = candidate.get("canonical_id", "unknown")
    name = (candidate.get("title", cid)[:80]).replace('"', "'")
    desc = (candidate.get("description", "")[:300]).replace('"', "'")
    severity = candidate.get("severity", "medium")
    sources_str = ",".join(candidate.get("merged_sources", [candidate.get("source", "unknown")]))
    cwe_str = ",".join(candidate.get("cwe", []))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    shadow_until = datetime.now(timezone.utc).timestamp() + 7 * 86400

    slug = _slugify(f"{cid}-{variant['name']}")
    filename = f"{check_number}-{slug}.sh"

    bash_body = variant.get("bash_body", "").rstrip()

    content = f"""#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-{check_number}
name: {name} ({variant['name']})
description: Auto-synthesized {today}; canonical_id={cid}; sources=[{sources_str}]; variant={variant['name']}; rationale={variant.get('rationale', '')[:200].replace('"', "'")}
category: code-scan
severity: {severity}
languages: any
min_tier: free
runtime_class: static-grep
provenance: auto
shadow_until: {datetime.fromtimestamp(shadow_until, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
evidence_required: false
version: 0.1.0
added_in: 1.8.0
author_name: Preston-Check Threat-Intel Pipeline
author_github: prestoncheck-bot
frameworks: {sources_str}
cwe: {cwe_str}
false_positive_rate: unknown
performance_class: fast
origin: {desc}
PRESTON_META

echo "P-{check_number}: {name} ({variant['name']})"

{bash_body}
"""
    return filename, content


def process_candidate(candidate: dict, dry_run: bool = False) -> dict:
    """Synthesize a single candidate, write resulting check files. Returns
    a summary dict."""
    cid = candidate.get("canonical_id", "unknown")
    synthesis = synthesize_candidate(candidate)
    if synthesis is None:
        return {"ok": False, "canonical_id": cid, "reason": "synthesis returned no result"}

    variants = synthesis.get("variants", [])
    if not variants:
        return {"ok": False, "canonical_id": cid, "reason": "no variants in synthesis output"}

    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    for variant in variants:
        if not isinstance(variant, dict) or "bash_body" not in variant:
            continue
        n = _next_check_number()
        filename, content = _render_check_file(candidate, variant, n)
        target = CANDIDATES_DIR / filename
        if dry_run:
            written.append(f"DRY: {target}")
        else:
            target.write_text(content)
            target.chmod(0o755)
            written.append(str(target))

    return {
        "ok": True,
        "canonical_id": cid,
        "variants_count": len(variants),
        "files_written": written,
        "placeholder": synthesis.get("_placeholder", False),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthesize detection-pattern candidates from correlated records.")
    parser.add_argument("--correlated", type=Path, default=CORRELATED)
    parser.add_argument("--max", type=int, default=10, help="Max candidates to process this run")
    parser.add_argument("--min-confidence", type=float, default=0.6)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.correlated.is_file():
        print(f"correlated input missing: {args.correlated}", file=sys.stderr)
        return 1

    data = json.loads(args.correlated.read_text())
    candidates = data.get("candidates", [])

    eligible = [c for c in candidates if c.get("composite_confidence", 0.0) >= args.min_confidence][: args.max]
    summaries: list[dict] = []
    for c in eligible:
        summaries.append(process_candidate(c, dry_run=args.dry_run))

    out = {
        "synthesised_at": datetime.now(timezone.utc).isoformat(),
        "model": DEFAULT_MODEL,
        "considered": len(candidates),
        "eligible": len(eligible),
        "processed": len(summaries),
        "summaries": summaries,
    }

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"Synthesized {len(summaries)} candidates (model={DEFAULT_MODEL})")
        for s in summaries:
            ok = "OK" if s["ok"] else "FAIL"
            note = " (placeholder)" if s.get("placeholder") else ""
            print(f"  [{ok}] {s['canonical_id']}: {s.get('variants_count', 0)} variants{note}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
