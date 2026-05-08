#!/usr/bin/env python3
"""tools/corpus_build.py

Build the positive and negative corpora reproducibly from manifests.

Reproducibility property: given a manifest at version N and the network
resources it points to (which are themselves pinned by commit SHA), the
build produces a tarball whose SHA256 is deterministic. This is what
lets the attestation log embed a corpus_hash that any third party can
re-derive and verify independently.

Manifest sources are restricted to a hard-coded allowlist:
  - cve-public-pocs / osv-pocs / exploit-db: positive corpus
  - gharchive / debian-source / ossf-fuzz: negative corpus
Entries with `source` outside this allowlist fail manifest validation,
preventing accidental direct-GitHub scraping (threat model M5).

Output:
  corpus/snapshots/positive-{date}.tar.gz with SHA256 sidecar
  corpus/snapshots/negative-{date}.tar.gz with SHA256 sidecar

Note: the manifest entries shipped today contain placeholder hashes
(64 zeros). The corpus bootstrap process — which resolves real
upstream commits, downloads the referenced files, and replaces the
placeholder hashes with real SHA256 values — runs as a separate
operator-driven workflow before the first auto-merge ships, because
it requires network resources at scale that are inappropriate for
in-CI runs. The build tool below is functional for the resolved
manifest.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import tarfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import yaml  # type: ignore[import-untyped]


_VALID_POSITIVE_SOURCES: frozenset[str] = frozenset(
    {"cve-public-pocs", "osv-pocs", "exploit-db"}
)
_VALID_NEGATIVE_SOURCES: frozenset[str] = frozenset(
    {"gharchive", "debian-source", "ossf-fuzz"}
)
_SHA256_HEX_RE_LEN = 64


def load_manifest(path: Path) -> dict:
    """Load a corpus manifest YAML and return the parsed dict."""
    return yaml.safe_load(path.read_text())


def validate_manifest(manifest: dict, side: str) -> list[str]:
    """Validate a manifest's structure and source allowlist. Returns list of
    issues (empty if valid)."""
    issues: list[str] = []
    if "corpus_version" not in manifest:
        issues.append("missing corpus_version")
    if "schema_version" not in manifest:
        issues.append("missing schema_version")
    if "entries" not in manifest or not isinstance(manifest["entries"], list):
        issues.append("missing or invalid entries list")
        return issues
    allowed = (
        _VALID_POSITIVE_SOURCES if side == "positive" else _VALID_NEGATIVE_SOURCES
    )
    for i, entry in enumerate(manifest["entries"]):
        if not isinstance(entry, dict):
            issues.append(f"entry {i}: not a dict")
            continue
        for required in ("id", "source", "upstream", "commit", "language"):
            if required not in entry:
                issues.append(f"entry {i} ({entry.get('id', '?')}): missing {required}")
        if "sha256" not in entry and "code_sample" not in entry:
            issues.append(
                f"entry {i} ({entry.get('id', '?')}): must have either sha256 (for upstream-pinned) or code_sample (for inline)"
            )
        if entry.get("source") not in allowed:
            issues.append(
                f"entry {i} ({entry.get('id', '?')}): source '{entry.get('source')}' "
                f"not in allowlist {sorted(allowed)}"
            )
        commit = str(entry.get("commit", ""))
        if commit and len(commit) != 40:
            issues.append(
                f"entry {i} ({entry.get('id', '?')}): commit must be 40-char hex SHA"
            )
        sha = str(entry.get("sha256", ""))
        if sha and len(sha) != _SHA256_HEX_RE_LEN:
            issues.append(
                f"entry {i} ({entry.get('id', '?')}): sha256 must be 64-char hex"
            )
    return issues


def _serialise_entry(entry: dict) -> bytes:
    """Canonical JSON serialisation of an entry for inclusion in the tarball."""
    return json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")


def build_tarball(manifest: dict, out_path: Path, side: str) -> tuple[Path, str]:
    """Build a deterministic tarball from the manifest entries.

    The tarball contains: one MANIFEST.json file with the canonical-sorted
    manifest, one entry per file under entries/{id}.json with the entry's
    full metadata, and one entries/{id}.expected-sha256 file recording the
    declared sha256.

    The actual upstream file contents are downloaded by a separate
    `corpus_resolve` step that operates on networked CI runners; in the
    no-network build path we serialise only the metadata, which is still
    sufficient for hash-equivalence checks of the manifest itself.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    members: list[tuple[str, bytes]] = []
    members.append(
        (
            "MANIFEST.json",
            json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8"),
        )
    )
    for entry in manifest.get("entries", []):
        eid = entry.get("id", "unknown")
        code_sample = entry.get("code_sample")
        if code_sample and not entry.get("sha256"):
            entry = dict(entry)
            entry["sha256"] = hashlib.sha256(code_sample.encode("utf-8")).hexdigest()
        members.append((f"entries/{eid}/metadata.json", _serialise_entry(entry)))
        members.append(
            (
                f"entries/{eid}/expected-sha256",
                str(entry.get("sha256", "")).encode("utf-8"),
            )
        )
        if code_sample:
            sample_filename = entry.get("file_path", "sample.txt")
            members.append(
                (
                    f"entries/{eid}/{sample_filename}",
                    code_sample.encode("utf-8"),
                )
            )

    members.sort(key=lambda m: m[0])

    tar_buf = BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            tf.addfile(info, BytesIO(data))

    raw = tar_buf.getvalue()
    gz_buf = BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=0, compresslevel=6) as gz:
        gz.write(raw)
    out_path.write_bytes(gz_buf.getvalue())

    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    sidecar = out_path.with_suffix(out_path.suffix + ".sha256")
    sidecar.write_text(f"{digest}  {out_path.name}\n")

    return out_path, digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a reproducible corpus tarball from its manifest.")
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to the manifest YAML",
    )
    parser.add_argument(
        "--side",
        choices=["positive", "negative"],
        required=True,
        help="Which corpus side this manifest represents",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("corpus/snapshots"),
        help="Output directory for the tarball + sha256 sidecar",
    )
    parser.add_argument(
        "--tag",
        type=str,
        default=None,
        help="Optional tag for the snapshot filename (defaults to today's UTC date)",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    issues = validate_manifest(manifest, args.side)
    if issues:
        print("Manifest validation failed:", file=sys.stderr)
        for it in issues:
            print(f"  - {it}", file=sys.stderr)
        return 1

    tag = args.tag or datetime.now(timezone.utc).strftime("%Y%m%d")
    out_path = args.out_dir / f"{args.side}-{tag}.tar.gz"
    written, digest = build_tarball(manifest, out_path, args.side)
    print(f"Wrote {written}")
    print(f"SHA256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
