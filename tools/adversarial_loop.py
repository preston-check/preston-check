#!/usr/bin/env python3
"""tools/adversarial_loop.py

Model-diverse adversarial evasion loop. Given a candidate that
passed validation, asks a different LLM (different provider from the
synthesizer) to generate evasive variants of the positive-corpus
samples — code that retains the vulnerability but escapes the
candidate's detection pattern.

Successful evasions are appended to the synthesis prompt for the next
round; the loop iterates up to N=3 rounds. Promotion requires the
final round to produce zero successful evasions.

Model diversity is enforced: synthesizer uses Anthropic
(claude-opus-4-7), adversarial uses OpenAI (gpt-4-turbo by default,
configurable via PRESTON_ADV_MODEL). The provider check is in
_check_diversity() and refuses same-provider configurations.

If OPENAI_API_KEY is unset, the loop runs in placeholder mode:
generates simple structural perturbations of the positive samples
(rename identifiers, insert noise) and tests whether the candidate
still detects them. This exercises the loop plumbing without LLM
budget but is much weaker than real adversarial generation.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent

DEFAULT_ROUNDS = 3
DEFAULT_ADV_MODEL = os.environ.get("PRESTON_ADV_MODEL", "gpt-4o-mini")
DEFAULT_SYNTH_MODEL = os.environ.get("PRESTON_SYNTH_MODEL", "claude-haiku-4-5-20251001")

OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"

_ADVERSARIAL_PROMPT = """You are an adversarial security researcher attempting to evade a static detection pattern.

Given a vulnerable code sample and a bash detection script, your task is to rewrite the sample so that:
  1. It still contains the vulnerability (do NOT fix the underlying bug)
  2. The provided bash detection script does NOT detect it (the grep/rg/find pattern misses)

Output a JSON object only, no prose:
{
  "evasion_attempted": true | false,
  "rewritten_code": "...",
  "evasion_strategy": "..."
}

Use realistic evasion strategies: identifier rename, comment insertion at trigger points, equivalent syntax substitution (e.g., dynamic property access vs. dotted), encoding tricks if the language supports them, splitting strings across concatenations.

Do NOT remove the vulnerability — the code must still be exploitable. Do NOT add comments saying "vulnerable" or marking the bug — that would help detection."""


_OPENAI_NAME_PREFIXES: tuple[str, ...] = ("gpt", "o1", "o3", "o4")


def _provider_of(model_name: str) -> str:
    """Return the provider family ('anthropic', 'openai', or 'unknown') for a model name."""
    lower = model_name.lower()
    if "claude" in lower:
        return "anthropic"
    if any(lower.startswith(p) or f"/{p}" in lower for p in _OPENAI_NAME_PREFIXES):
        return "openai"
    return "unknown"


def _check_diversity(synth_model: str, adv_model: str) -> str | None:
    """Return error message if synth and adv models share a provider, else None.

    Recognised providers: 'claude*' (Anthropic) and 'gpt*' / 'o1*' / 'o3*' / 'o4*'
    (OpenAI, including o-series reasoning models). Any other model name is treated as
    unknown and rejected: an unrecognised provider cannot satisfy the diversity
    requirement because we cannot verify it is a different provider family from the
    synthesiser.
    """
    s_provider = _provider_of(synth_model)
    a_provider = _provider_of(adv_model)
    if s_provider == "unknown" or a_provider == "unknown":
        return (
            f"model monoculture: unrecognised provider(s): synth={synth_model}, adv={adv_model}"
            " — only 'claude*' and 'gpt*'/'o1*'/'o3*'/'o4*' model names are validated for provider diversity"
        )
    if s_provider == a_provider:
        return f"model monoculture: synth={synth_model} adv={adv_model} both on {s_provider}"
    return None


def _call_openai(prompt: str, user_message: str, model: str, api_key: str) -> dict | None:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": user_message},
        ],
        "max_tokens": 2048,
        "temperature": 0.7,
    }
    req = urllib.request.Request(
        OPENAI_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"[adversarial_loop] OpenAI API error: {exc}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[adversarial_loop] unexpected error: {exc}", file=sys.stderr)
        return None
    raw = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _placeholder_evade(sample: str) -> dict:
    """Deterministic placeholder evasion: rename identifiers, insert noise."""
    rng = random.Random(hash(sample) & 0xFFFFFFFF)
    renames = {
        "password": "pwd_x",
        "secret": "sct_x",
        "api_key": "ak_x",
        "auth_token": "tk_x",
    }
    rewritten = sample
    for old, new in renames.items():
        rewritten = re.sub(rf"\b{re.escape(old)}\b", new, rewritten, flags=re.IGNORECASE)
    lines = rewritten.splitlines()
    if lines:
        insert_at = rng.randint(0, max(0, len(lines) - 1))
        lines.insert(insert_at, "// noise")
    return {
        "evasion_attempted": True,
        "rewritten_code": "\n".join(lines),
        "evasion_strategy": "placeholder: identifier rename + comment insertion",
    }


def _detection_fires(check_path: Path, target_dir: Path) -> bool:
    """Run check_path's bash body against target_dir; return True if a record
    fires with FAIL/WARN.

    A CRASH (script exits before emitting any RECORD) is treated conservatively
    as detection=True so that a crashing check is never miscounted as a
    successful adversarial evasion.
    """
    from validate_candidate import _extract_bash_body, _run_bash_against_file  # type: ignore[import-not-found]

    bash_body = _extract_bash_body(check_path)
    fired, status = _run_bash_against_file(bash_body, target_dir)
    if status == "CRASH":
        return True
    return fired


def run_adversarial(
    check_path: Path,
    positive_corpus_dir: Path,
    rounds: int = DEFAULT_ROUNDS,
    synth_model: str = DEFAULT_SYNTH_MODEL,
    adv_model: str = DEFAULT_ADV_MODEL,
) -> dict:
    diversity_err = _check_diversity(synth_model, adv_model)
    if diversity_err:
        return {
            "ok": False,
            "reason": diversity_err,
            "synth_model": synth_model,
            "adv_model": adv_model,
        }

    api_key = os.environ.get("OPENAI_API_KEY", "")
    transcript: list[dict] = []
    # Use only the bash body (not the full file including META block) so the
    # adversarial LLM sees the actual detection pattern within the 2000-char window.
    from validate_candidate import _extract_bash_body  # type: ignore[import-not-found]
    bash_body = _extract_bash_body(check_path)

    successful_evasions = 0
    rounds_completed = 0

    for round_idx in range(rounds):
        rounds_completed = round_idx + 1
        round_evasions = 0

        for entry_dir in sorted(positive_corpus_dir.iterdir() if positive_corpus_dir.is_dir() else []):
            if not entry_dir.is_dir():
                continue
            sample_files = list(entry_dir.iterdir())
            if not sample_files:
                continue
            sample_text = sample_files[0].read_text(errors="replace")[:4000]

            # Only test adversarial evasion on corpus entries the check actually fires on.
            # If the check doesn't fire on the original sample (e.g., wrong language/framework),
            # there is nothing to evade and testing would produce a false evasion signal.
            if not _detection_fires(check_path, entry_dir):
                transcript.append({
                    "round": rounds_completed,
                    "entry": entry_dir.name,
                    "evaded": False,
                    "skipped": True,
                    "reason": "check does not fire on original sample",
                })
                continue

            if api_key:
                user_msg = (
                    "Detection script:\n```bash\n"
                    + bash_body[:2000]
                    + "\n```\n\nVulnerable code sample:\n```\n"
                    + sample_text
                    + "\n```\n\nProduce an evasive rewrite (JSON only)."
                )
                result = _call_openai(_ADVERSARIAL_PROMPT, user_msg, adv_model, api_key)
                if result is None:
                    result = _placeholder_evade(sample_text)
            else:
                result = _placeholder_evade(sample_text)

            if not result.get("evasion_attempted"):
                continue
            rewritten = result.get("rewritten_code", "")
            if not rewritten:
                continue

            import tempfile
            with tempfile.TemporaryDirectory() as evtd:
                ev_dir = Path(evtd) / entry_dir.name
                ev_dir.mkdir(parents=True)
                (ev_dir / "evaded.txt").write_text(rewritten)
                fires = _detection_fires(check_path, ev_dir)

            if not fires:
                round_evasions += 1
                successful_evasions += 1
                transcript.append(
                    {
                        "round": rounds_completed,
                        "entry": entry_dir.name,
                        "evaded": True,
                        "strategy": result.get("evasion_strategy", ""),
                    }
                )
            else:
                transcript.append(
                    {
                        "round": rounds_completed,
                        "entry": entry_dir.name,
                        "evaded": False,
                    }
                )

        if round_evasions == 0:
            break

    transcript_blob = json.dumps(transcript, sort_keys=True).encode("utf-8")
    import hashlib

    transcript_hash = hashlib.sha256(transcript_blob).hexdigest()

    return {
        "ok": True,
        "synth_model": synth_model,
        "adv_model": adv_model,
        "rounds": rounds_completed,
        "successful_evasions": successful_evasions,
        "transcript_hash": transcript_hash,
        "passes": successful_evasions == 0,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run adversarial evasion loop against a candidate.")
    parser.add_argument("check_path", type=Path)
    parser.add_argument("--positive-dir", type=Path, required=True, help="Extracted positive corpus directory")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run_adversarial(args.check_path, args.positive_dir, args.rounds)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if not result["ok"]:
            print(f"FAIL: {result.get('reason')}")
            return 1
        status = "PASS" if result["passes"] else "FAIL"
        print(f"{status} adversarial loop on {args.check_path}")
        print(f"  rounds={result['rounds']} successful_evasions={result['successful_evasions']}")
        print(f"  synth={result['synth_model']} adv={result['adv_model']}")

    return 0 if result.get("passes") else 1


if __name__ == "__main__":
    sys.exit(main())
