#!/usr/bin/env python3
"""tools/orchestrate.py

End-to-end auto-merge orchestrator. Pulls candidates from the queue,
runs them through every gate, signs an attestation, and either commits
the passing candidates to the catalog (with a per-candidate attestation
file) or routes failures back to the synthesis-retry queue.

Pipeline order:
  1. Correlate queued source records (tools/correlator.py)
  2. Synthesize candidates from correlated records (tools/synthesize.py)
  3. For each synthesized candidate:
     a. sandbox_validate → reject on fail
     b. validate_candidate (TPR/FPR/stability) → reject on fail
     c. adversarial_loop → reject on evasion success
     d. attest sign → write attestation JSON to attestations/
     e. move check from .preston-check/candidates/ → checks/community/accepted/
  4. Emit summary JSON for the workflow to publish in PR body

Kill switch: env var PRESTON_AUTOMERGE_ENABLED must be "true". If
unset or any other value, dry-run mode (no commits, no attestations
signed). This lets the orchestrator run end-to-end safely while the
operator is verifying behaviour, then flip the switch when ready.

Workflow-file branch protection (see threat model C3) is enforced at
the GitHub level, not by this script. This script's role is to
produce the candidate + attestation; the workflow is what merges the
PR, and that workflow itself can only be modified through the
hardware-key-signed-commit branch protection.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
TOOLS = ROOT / "tools"
ATTESTATIONS = ROOT / "attestations"
ACCEPTED = ROOT / "checks" / "community" / "accepted"
RETRY_QUEUE = ROOT / ".preston-check" / "retry-queue"
SUMMARY_FILE = ROOT / ".preston-check" / "orchestrate-summary.json"

CANDIDATES_DIR = ROOT / ".preston-check" / "candidates"


def _run(cmd: list[str], capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=capture, text=True, cwd=ROOT)


def _gate_sandbox(check_path: Path) -> dict[str, Any]:
    res = _run(
        [
            sys.executable,
            str(TOOLS / "sandbox_validate.py"),
            str(check_path),
            "--json",
        ]
    )
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return {"pass": False, "reasons": ["sandbox output unparseable"]}


def _gate_validate(check_path: Path, positive: Path, negative: Path) -> dict[str, Any]:
    res = _run(
        [
            sys.executable,
            str(TOOLS / "validate_candidate.py"),
            str(check_path),
            "--positive",
            str(positive),
            "--negative",
            str(negative),
            "--json",
        ]
    )
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return {"pass": False, "metrics": {}, "reason": "validate output unparseable"}


def _gate_adversarial(check_path: Path, positive_dir: Path) -> dict[str, Any]:
    res = _run(
        [
            sys.executable,
            str(TOOLS / "adversarial_loop.py"),
            str(check_path),
            "--positive-dir",
            str(positive_dir),
            "--json",
        ]
    )
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return {"passes": False, "reason": "adversarial output unparseable"}


def _build_attestation(
    candidate: dict,
    sandbox_result: dict,
    validate_result: dict,
    adversarial_result: dict,
    check_id: str,
) -> dict:
    return {
        "attestation_version": "1.0",
        "check_id": check_id,
        "source": {
            "type": ",".join(candidate.get("merged_sources", [])) or candidate.get("source", "unknown"),
            "id": candidate.get("canonical_id", ""),
            "fetched_at": candidate.get("first_seen", datetime.now(timezone.utc).isoformat()),
        },
        "synthesis": {
            "model": os.environ.get("PRESTON_SYNTH_MODEL", "claude-haiku-4-5-20251001"),
            "prompt_template_hash": "synthesis-v1.0.0",
            "ts": datetime.now(timezone.utc).isoformat(),
        },
        "sandbox": {
            "validator_version": sandbox_result.get("validator_version", "0.2.0"),
            "pass": sandbox_result.get("pass", False),
            "reasons": sandbox_result.get("reasons", []),
        },
        "validation": {
            "corpus_positive_hash": validate_result.get("corpus_hashes", {}).get("positive", ""),
            "corpus_negative_hash": validate_result.get("corpus_hashes", {}).get("negative", ""),
            "tpr": validate_result.get("metrics", {}).get("tpr", 0.0),
            "fpr": validate_result.get("metrics", {}).get("fpr", 0.0),
            "stability": validate_result.get("metrics", {}).get("stability", 0.0),
        },
        "adversarial": {
            "synth_model": adversarial_result.get("synth_model", ""),
            "adv_model": adversarial_result.get("adv_model", ""),
            "rounds": adversarial_result.get("rounds", 0),
            "transcript_hash": adversarial_result.get("transcript_hash", ""),
            "passes": adversarial_result.get("passes", False),
        },
        "merged_at": datetime.now(timezone.utc).isoformat(),
    }


def _sign_attestation(payload: dict, check_id: str, dry_run: bool) -> Path | None:
    ATTESTATIONS.mkdir(parents=True, exist_ok=True)
    payload_path = ATTESTATIONS / f"{check_id}.payload.json"
    payload_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    private_key = os.environ.get("ATTESTATION_PRIVATE_KEY_PATH", "")
    if not private_key or dry_run:
        return None
    if not Path(private_key).is_file():
        return None

    signed_path = ATTESTATIONS / f"{check_id}.signed.json"
    res = _run(
        [
            sys.executable,
            str(TOOLS / "attest.py"),
            "sign",
            "--payload",
            str(payload_path),
            "--private-key",
            private_key,
            "--out",
            str(signed_path),
        ]
    )
    if res.returncode != 0:
        return None
    return signed_path


def process_candidate(
    candidate_check: Path,
    candidate_meta: dict,
    positive_corpus: Path,
    negative_corpus: Path,
    dry_run: bool,
) -> dict:
    """Run a single candidate through every gate. Returns a summary."""
    check_id = candidate_check.stem.split("-")[0]
    summary: dict[str, Any] = {
        "candidate_check": str(candidate_check),
        "check_id": check_id,
        "canonical_id": candidate_meta.get("canonical_id", ""),
        "outcome": "pending",
    }

    sandbox = _gate_sandbox(candidate_check)
    summary["sandbox"] = sandbox
    if not sandbox.get("pass"):
        summary["outcome"] = "rejected:sandbox"
        _route_to_retry(candidate_check, summary)
        return summary

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        from validate_candidate import _extract_corpus_to_tmpdir  # type: ignore[import-not-found]

        positive_dir = _extract_corpus_to_tmpdir(positive_corpus, Path(td), "positive")

        validate = _gate_validate(candidate_check, positive_corpus, negative_corpus)
        summary["validate"] = validate
        if not validate.get("pass"):
            summary["outcome"] = "rejected:validate"
            _route_to_retry(candidate_check, summary)
            return summary

        adversarial = _gate_adversarial(candidate_check, positive_dir)
    summary["adversarial"] = adversarial
    if not adversarial.get("passes", False):
        summary["outcome"] = "rejected:adversarial"
        _route_to_retry(candidate_check, summary)
        return summary

    attestation = _build_attestation(candidate_meta, sandbox, validate, adversarial, check_id)
    signed = _sign_attestation(attestation, check_id, dry_run)
    summary["attestation"] = {"path": str(signed) if signed else None, "signed": signed is not None}

    if dry_run:
        summary["outcome"] = "would-promote"
    else:
        ACCEPTED.mkdir(parents=True, exist_ok=True)
        target = ACCEPTED / candidate_check.name
        shutil.move(str(candidate_check), str(target))
        summary["promoted_to"] = str(target)
        summary["outcome"] = "promoted"

    return summary


def _route_to_retry(candidate_check: Path, summary: dict) -> None:
    RETRY_QUEUE.mkdir(parents=True, exist_ok=True)
    target = RETRY_QUEUE / candidate_check.name
    if candidate_check.is_file():
        shutil.copy(str(candidate_check), str(target))
    (RETRY_QUEUE / f"{candidate_check.stem}.summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the end-to-end auto-merge orchestrator.")
    parser.add_argument("--positive-corpus", type=Path, required=True)
    parser.add_argument("--negative-corpus", type=Path, required=True)
    parser.add_argument("--correlated", type=Path, default=ROOT / ".preston-check" / "correlated.json")
    parser.add_argument("--max-candidates", type=int, default=5)
    args = parser.parse_args()

    automerge = os.environ.get("PRESTON_AUTOMERGE_ENABLED", "false").lower() == "true"
    dry_run = not automerge

    if not args.correlated.is_file():
        print(f"correlated input missing: {args.correlated}", file=sys.stderr)
        return 1

    correlated = json.loads(args.correlated.read_text()).get("candidates", [])
    by_id = {c.get("canonical_id", ""): c for c in correlated}

    summaries: list[dict] = []
    candidate_files = sorted(CANDIDATES_DIR.glob("*.sh")) if CANDIDATES_DIR.is_dir() else []
    for cf in candidate_files[: args.max_candidates]:
        cid_match = ""
        for cid in by_id.keys():
            if cid.lower().replace("-", "").replace("_", "") in cf.stem.lower().replace("-", "").replace("_", ""):
                cid_match = cid
                break
        meta = by_id.get(cid_match, {"canonical_id": cf.stem})
        summary = process_candidate(cf, meta, args.positive_corpus, args.negative_corpus, dry_run)
        summaries.append(summary)

    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.write_text(
        json.dumps(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "automerge_enabled": automerge,
                "dry_run": dry_run,
                "processed": len(summaries),
                "summaries": summaries,
            },
            indent=2,
            sort_keys=True,
        )
    )

    print(f"Orchestration complete (automerge={automerge}, dry_run={dry_run})")
    counts: dict[str, int] = {}
    for s in summaries:
        counts[s["outcome"]] = counts.get(s["outcome"], 0) + 1
    for outcome, n in sorted(counts.items()):
        print(f"  {outcome}: {n}")
    print(f"Summary: {SUMMARY_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
