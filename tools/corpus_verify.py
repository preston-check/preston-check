#!/usr/bin/env python3
"""tools/corpus_verify.py

Verify that a corpus tarball matches its manifest by re-deriving the
expected SHA256 from the manifest and comparing against the tarball's
sidecar sha256 file.

This is the reproducibility check that lets attestations cite a corpus
hash and have any third party independently verify the validation
provenance. If a corpus tarball is tampered with after build, this
catches it. If a manifest is updated without rebuilding, this catches
that too.

Exit codes: 0 on match, 1 on mismatch, 2 on missing inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from corpus_build import build_tarball, load_manifest, validate_manifest  # type: ignore[import-not-found]


def verify(manifest_path: Path, tarball_path: Path, side: str) -> dict:
    """Rebuild the tarball from the manifest in a temp location and compare hash."""
    if not manifest_path.is_file():
        return {"ok": False, "reason": f"manifest missing: {manifest_path}"}
    if not tarball_path.is_file():
        return {"ok": False, "reason": f"tarball missing: {tarball_path}"}

    manifest = load_manifest(manifest_path)
    issues = validate_manifest(manifest, side)
    if issues:
        return {"ok": False, "reason": "manifest invalid", "issues": issues}

    actual = hashlib.sha256(tarball_path.read_bytes()).hexdigest()

    sidecar = tarball_path.with_suffix(tarball_path.suffix + ".sha256")
    expected: str | None = None
    if sidecar.is_file():
        expected = sidecar.read_text().split()[0].strip()

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        rebuild_path = Path(td) / "rebuild.tar.gz"
        _, rebuild_hash = build_tarball(manifest, rebuild_path, side)

    return {
        "ok": rebuild_hash == actual and (expected is None or expected == actual),
        "tarball_hash": actual,
        "rebuild_hash": rebuild_hash,
        "sidecar_hash": expected,
        "match_rebuild": rebuild_hash == actual,
        "match_sidecar": expected == actual if expected else True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a corpus tarball matches its manifest.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tarball", type=Path, required=True)
    parser.add_argument("--side", choices=["positive", "negative"], required=True)
    args = parser.parse_args()

    result = verify(args.manifest, args.tarball, args.side)
    if result["ok"]:
        print(f"OK    {args.tarball}")
        print(f"      hash: {result['tarball_hash']}")
        return 0
    else:
        print(f"FAIL  {args.tarball}")
        for k, v in result.items():
            if k != "ok":
                print(f"      {k}: {v}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
