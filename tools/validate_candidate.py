#!/usr/bin/env python3
"""tools/validate_candidate.py

Validate a synthesized candidate by computing TPR (against the
positive corpus) and FPR (against the negative corpus), plus a
stability score (does the pattern still fire under light syntactic
perturbations).

A candidate's bash body is run inside a fresh subshell against each
corpus file matching the candidate's declared language/framework.
The candidate's own synthetic fixtures are tested first as a sanity
check — a candidate that fails its own fixtures is rejected before
expensive corpus testing.

Promotion thresholds (defaults; configurable):
  - TPR >= 0.85
  - FPR <= 0.02
  - stability >= 0.90
  - own-fixture round-trip == pass

Output: JSON with all four metrics, per-file outcomes, and a
pass/fail decision against the thresholds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
DEFAULT_TPR = 0.85
DEFAULT_FPR = 0.02
DEFAULT_STABILITY = 0.90


def _extract_meta(check_path: Path) -> dict:
    """Extract the PRESTON_META block from a check file."""
    src = check_path.read_text()
    m = re.search(
        r":\s*<<\s*['\"]?PRESTON_META['\"]?\s*\n(.*?)\nPRESTON_META",
        src,
        re.DOTALL,
    )
    if not m:
        return {}
    meta_text = m.group(1)
    out: dict[str, str] = {}
    for line in meta_text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def _extract_bash_body(check_path: Path) -> str:
    """Extract the bash body of a check (everything after the META block
    and the optional initial echo line)."""
    src = check_path.read_text()
    after_meta = re.split(r"PRESTON_META\s*\n", src, maxsplit=1)
    body = after_meta[1] if len(after_meta) > 1 else src
    body = re.sub(r"^\s*echo\s+\"P-\d+:.*?\"\s*\n", "", body, count=1)
    return body


def _run_bash_against_file(
    bash_body: str, target_dir: Path, timeout: int = 30
) -> tuple[bool, str]:
    """Run the candidate's bash body in a fresh subshell with SOURCE_DIR
    set to target_dir. Returns (fired, last_record_status)."""
    record_log = []

    runner = (
        "set -euo pipefail\n"
        f'export SOURCE_DIR={shlex_quote(str(target_dir))}\n'
        'PATH=/usr/bin:/bin\n'
        'unset IFS\n'
        'record() { printf "RECORD\\t%s\\t%s\\t%s\\n" "$1" "$2" "$3"; }\n'
        'export -f record\n'
        + bash_body
    )

    try:
        result = subprocess.run(
            ["bash", "-c", runner],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "SOURCE_DIR": str(target_dir)},
        )
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as exc:
        return False, f"ERROR:{exc}"

    last_status = ""
    fired = False
    for line in result.stdout.splitlines():
        if line.startswith("RECORD\t"):
            parts = line.split("\t")
            if len(parts) >= 3:
                last_status = parts[1]
                if last_status in ("FAIL", "WARN"):
                    fired = True
    return fired, last_status or "NO_RECORD"


def shlex_quote(s: str) -> str:
    """Quote a string for safe inclusion in a bash command."""
    if not s or re.search(r"[^\w@%+=:,./-]", s):
        return "'" + s.replace("'", "'\"'\"'") + "'"
    return s


def _extract_corpus_to_tmpdir(tarball: Path, tmp: Path, side: str) -> Path:
    """Extract a corpus tarball to a tempdir. Returns the dir to use as
    SOURCE_DIR per file (each entry is realised as one file in a subdir)."""
    out_dir = tmp / side
    out_dir.mkdir(parents=True, exist_ok=True)
    if not tarball.is_file():
        return out_dir
    with tarfile.open(tarball, "r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if not member.name.startswith("entries/") or not member.name.endswith(".json"):
                continue
            try:
                fobj = tf.extractfile(member)
                if not fobj:
                    continue
                entry = json.loads(fobj.read().decode("utf-8"))
            except Exception:
                continue

            entry_dir = out_dir / entry.get("id", "unknown")
            entry_dir.mkdir(parents=True, exist_ok=True)
            file_path = entry_dir / "sample.txt"
            content = (
                f"// {entry.get('id', '')} — {entry.get('language', '')}/{entry.get('framework', '')}\n"
                f"// vuln_class: {entry.get('vuln_class', 'n/a')}\n"
                f"// upstream: {entry.get('upstream', '')}\n"
                f"// description: {entry.get('description', '')}\n"
            )
            file_path.write_text(content)
    return out_dir


def _perturb_directory(src: Path, dst: Path) -> None:
    """Light syntactic perturbations: insert blank lines, comment lines,
    rename whitespace patterns. Used for stability scoring."""
    rng = random.Random(0)
    for entry_dir in src.iterdir():
        if not entry_dir.is_dir():
            continue
        out_dir = dst / entry_dir.name
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in entry_dir.iterdir():
            if not f.is_file():
                continue
            text = f.read_text()
            lines = text.splitlines()
            perturbed: list[str] = []
            for line in lines:
                if rng.random() < 0.2:
                    perturbed.append("")
                if rng.random() < 0.15:
                    perturbed.append("// noise comment")
                perturbed.append(line.replace("  ", "    "))
            (out_dir / f.name).write_text("\n".join(perturbed))


def validate(
    check_path: Path,
    positive_corpus: Path,
    negative_corpus: Path,
    tpr_threshold: float = DEFAULT_TPR,
    fpr_threshold: float = DEFAULT_FPR,
    stability_threshold: float = DEFAULT_STABILITY,
) -> dict[str, Any]:
    bash_body = _extract_bash_body(check_path)
    meta = _extract_meta(check_path)

    fixture_pos_path = check_path.with_name(check_path.stem + ".pos.txt")
    fixture_neg_path = check_path.with_name(check_path.stem + ".neg.txt")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        if fixture_pos_path.is_file() and fixture_neg_path.is_file():
            pos_dir = tmp / "fixture-pos"
            neg_dir = tmp / "fixture-neg"
            pos_dir.mkdir(parents=True)
            neg_dir.mkdir(parents=True)
            shutil.copy(fixture_pos_path, pos_dir / "sample.txt")
            shutil.copy(fixture_neg_path, neg_dir / "sample.txt")
            fired_pos, _ = _run_bash_against_file(bash_body, pos_dir)
            fired_neg, _ = _run_bash_against_file(bash_body, neg_dir)
            fixture_roundtrip = fired_pos and not fired_neg
        else:
            fixture_roundtrip = True

        pos_dir = _extract_corpus_to_tmpdir(positive_corpus, tmp, "positive")
        neg_dir = _extract_corpus_to_tmpdir(negative_corpus, tmp, "negative")

        pos_results: list[tuple[str, bool]] = []
        for entry_dir in sorted(pos_dir.iterdir()):
            if not entry_dir.is_dir():
                continue
            fired, status = _run_bash_against_file(bash_body, entry_dir)
            pos_results.append((entry_dir.name, fired))

        neg_results: list[tuple[str, bool]] = []
        for entry_dir in sorted(neg_dir.iterdir()):
            if not entry_dir.is_dir():
                continue
            fired, status = _run_bash_against_file(bash_body, entry_dir)
            neg_results.append((entry_dir.name, fired))

        perturb_dir = tmp / "perturbed"
        perturb_dir.mkdir(parents=True)
        _perturb_directory(pos_dir, perturb_dir)
        perturb_results: list[tuple[str, bool]] = []
        for entry_dir in sorted(perturb_dir.iterdir()):
            if not entry_dir.is_dir():
                continue
            fired, _ = _run_bash_against_file(bash_body, entry_dir)
            perturb_results.append((entry_dir.name, fired))

    tpr = sum(1 for _, f in pos_results if f) / len(pos_results) if pos_results else 0.0
    fpr = sum(1 for _, f in neg_results if f) / len(neg_results) if neg_results else 0.0

    stability = 0.0
    if pos_results and perturb_results:
        original = {n: f for n, f in pos_results}
        agree = sum(1 for n, f in perturb_results if original.get(n) == f)
        stability = agree / len(perturb_results)

    decision_pass = (
        fixture_roundtrip
        and tpr >= tpr_threshold
        and fpr <= fpr_threshold
        and stability >= stability_threshold
    )

    return {
        "check_path": str(check_path),
        "validator_version": "0.1.0",
        "metrics": {
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "stability": round(stability, 4),
            "fixture_roundtrip": fixture_roundtrip,
        },
        "thresholds": {
            "tpr": tpr_threshold,
            "fpr": fpr_threshold,
            "stability": stability_threshold,
        },
        "corpus_hashes": {
            "positive": _file_sha(positive_corpus),
            "negative": _file_sha(negative_corpus),
        },
        "per_file": {
            "positive": [{"id": n, "fired": f} for n, f in pos_results],
            "negative": [{"id": n, "fired": f} for n, f in neg_results],
            "perturbed": [{"id": n, "fired": f} for n, f in perturb_results],
        },
        "pass": decision_pass,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def _file_sha(p: Path) -> str:
    if not p.is_file():
        return ""
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a candidate against positive/negative corpora.")
    parser.add_argument("check_path", type=Path)
    parser.add_argument("--positive", type=Path, required=True)
    parser.add_argument("--negative", type=Path, required=True)
    parser.add_argument("--tpr-threshold", type=float, default=DEFAULT_TPR)
    parser.add_argument("--fpr-threshold", type=float, default=DEFAULT_FPR)
    parser.add_argument("--stability-threshold", type=float, default=DEFAULT_STABILITY)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = validate(
        args.check_path,
        args.positive,
        args.negative,
        args.tpr_threshold,
        args.fpr_threshold,
        args.stability_threshold,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        m = result["metrics"]
        print(f"{'PASS' if result['pass'] else 'FAIL'}  {args.check_path}")
        print(f"  tpr={m['tpr']} fpr={m['fpr']} stability={m['stability']} fixture_rt={m['fixture_roundtrip']}")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
