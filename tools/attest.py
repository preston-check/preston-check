#!/usr/bin/env python3
"""tools/attest.py

Public attestation log for catalog changes.

Every catalog change ships with a signed JSON attestation that records:
  - Source provenance (CVE/advisory id, source name, fetch timestamp)
  - Synthesis provenance (model, prompt template hash, variant, fixture
    pass status, timestamp)
  - Sandbox provenance (validator version, pass result, reasons)
  - Validation provenance (corpus hashes, TPR, FPR, stability)
  - Adversarial provenance (model used, rounds completed, transcript
    hash)
  - Gate effectiveness scores at the time of merge
  - Ed25519 signature

The attestation key is held as a Cloudflare Worker / GitHub Actions
secret `ATTESTATION_PRIVATE_KEY` (PEM-encoded Ed25519). The public
half is checked into the repo at `lib/attestation_pubkey.pem` and is
how any third party verifies an attestation.

This file provides three subcommands:
  - `sign`   : create a signed attestation from a JSON payload
  - `verify` : verify a signed attestation against the public key
  - `genkey` : generate a fresh keypair (operator one-time setup)

The signed attestation is a JSON object with a top-level `signature`
field whose value is base64(ed25519_sign(canonical_json(payload))).
The signature covers every other top-level field in canonical JSON
form (sort_keys=True, separators=(',', ':')).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonical(payload: dict) -> bytes:
    """Canonical JSON representation: sorted keys, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _load_private_key(pem_path: Path) -> Ed25519PrivateKey:
    pem = pem_path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"key at {pem_path} is not an Ed25519 private key")
    return key


def _load_public_key(pem_path: Path) -> Ed25519PublicKey:
    pem = pem_path.read_bytes()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise SystemExit(f"key at {pem_path} is not an Ed25519 public key")
    return key


def sign_attestation(payload: dict[str, Any], private_key_pem: Path) -> dict[str, Any]:
    """Sign an attestation payload and return the full signed object."""
    if "signature" in payload:
        raise ValueError("payload already contains 'signature' field; refusing to overwrite")

    out = dict(payload)
    out.setdefault("attestation_version", "1.0")

    canonical = _canonical(out)
    out["payload_sha256"] = hashlib.sha256(canonical).hexdigest()

    re_canonical = _canonical(out)
    private = _load_private_key(private_key_pem)
    sig = private.sign(re_canonical)
    out["signature"] = "ed25519:" + base64.b64encode(sig).decode("ascii")

    return out


def verify_attestation(signed: dict[str, Any], public_key_pem: Path) -> tuple[bool, str]:
    """Verify a signed attestation. Returns (ok, reason)."""
    if "signature" not in signed:
        return False, "no signature field"
    sig_str = signed["signature"]
    if not sig_str.startswith("ed25519:"):
        return False, f"unsupported signature scheme in {sig_str[:32]}"
    try:
        sig = base64.b64decode(sig_str[len("ed25519:") :])
    except Exception as exc:
        return False, f"signature base64 decode error: {exc}"

    payload_for_verify = {k: v for k, v in signed.items() if k != "signature"}
    canonical = _canonical(payload_for_verify)

    declared_hash = signed.get("payload_sha256")
    if declared_hash:
        recomputed = hashlib.sha256(
            _canonical({k: v for k, v in payload_for_verify.items() if k != "payload_sha256"})
        ).hexdigest()
        if declared_hash != recomputed:
            return False, "payload_sha256 mismatch (attestation contents changed)"

    public = _load_public_key(public_key_pem)
    try:
        public.verify(sig, canonical)
    except Exception as exc:
        return False, f"signature verification failed: {exc}"

    return True, "ok"


def generate_keypair(private_out: Path, public_out: Path) -> None:
    """Generate a fresh Ed25519 keypair and write to the given paths."""
    if private_out.exists():
        raise SystemExit(f"refusing to overwrite existing private key at {private_out}")
    if public_out.exists():
        raise SystemExit(f"refusing to overwrite existing public key at {public_out}")

    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_out.parent.mkdir(parents=True, exist_ok=True)
    public_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_bytes(private_pem)
    public_out.write_bytes(public_pem)
    private_out.chmod(0o600)


def _cmd_sign(args: argparse.Namespace) -> int:
    payload_in = json.loads(args.payload.read_text())
    signed = sign_attestation(payload_in, args.private_key)
    args.out.write_text(json.dumps(signed, indent=2, sort_keys=True))
    print(f"signed -> {args.out}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    signed = json.loads(args.attestation.read_text())
    ok, reason = verify_attestation(signed, args.public_key)
    if ok:
        print(f"OK    {args.attestation}")
        return 0
    print(f"FAIL  {args.attestation}: {reason}", file=sys.stderr)
    return 1


def _cmd_genkey(args: argparse.Namespace) -> int:
    generate_keypair(args.private_out, args.public_out)
    print(f"private key -> {args.private_out} (chmod 0600)")
    print(f"public key  -> {args.public_out}")
    print()
    print("Next steps:")
    print(f"  1. Commit {args.public_out} to the repo")
    print(f"  2. Add the contents of {args.private_out} as the GitHub repo secret ATTESTATION_PRIVATE_KEY")
    print(f"  3. Delete the local private-key file (operator's hardware-bound key takes over)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign and verify Preston-Check attestations.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sign", help="Sign an attestation payload")
    s.add_argument("--payload", type=Path, required=True, help="JSON payload to sign")
    s.add_argument("--private-key", type=Path, required=True, help="PEM file containing Ed25519 private key")
    s.add_argument("--out", type=Path, required=True, help="Output path for signed attestation")
    s.set_defaults(func=_cmd_sign)

    v = sub.add_parser("verify", help="Verify a signed attestation")
    v.add_argument("--attestation", type=Path, required=True, help="Signed attestation JSON")
    v.add_argument("--public-key", type=Path, default=Path("lib/attestation_pubkey.pem"))
    v.set_defaults(func=_cmd_verify)

    g = sub.add_parser("genkey", help="Generate a fresh Ed25519 keypair")
    g.add_argument("--private-out", type=Path, required=True)
    g.add_argument("--public-out", type=Path, required=True)
    g.set_defaults(func=_cmd_genkey)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
