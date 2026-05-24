#!/usr/bin/env python3
"""tests/threat-intel/test_pipeline.py

End-to-end tests for the auto-evolving threat-intel pipeline. Covers:

  - sandbox_validate: AST walker rejects denied bash, accepts legitimate
  - sandbox_redteam: catch rate threshold met
  - corpus_build: produces deterministic hash; verify roundtrips
  - attest sign/verify: sign ↔ verify roundtrip; tamper detection
  - synthesize: placeholder path produces valid candidates
  - validate_candidate: extracts metrics from candidate vs corpora
  - dual_use_audit: all four campaigns produce scores

Run with: PYTHONPATH=tools pytest tests/threat-intel/test_pipeline.py
or: /tmp/preston-venv/bin/python tests/threat-intel/test_pipeline.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


class SandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        from sandbox_validate import validate_check  # type: ignore[import-not-found]

        self.validate_check = validate_check

    def _make_check(self, body: str, provenance: str = "auto") -> Path:
        td = Path(tempfile.mkdtemp())
        p = td / "test.sh"
        p.write_text(
            f"""#!/bin/bash
: <<'PRESTON_META'
id: P-TEST
provenance: {provenance}
PRESTON_META
{body}
"""
        )
        return p

    def test_legitimate_grep_passes(self) -> None:
        p = self._make_check(
            'SRC="${SOURCE_DIR:-.}"\n'
            'hits=$(grep -rn "password" "$SRC" 2>/dev/null || true)\n'
            'record "PASS" "test" "ok"'
        )
        self.assertTrue(self.validate_check(p)["pass"])

    def test_eval_rejected(self) -> None:
        p = self._make_check('eval "ls"')
        self.assertFalse(self.validate_check(p)["pass"])

    def test_curl_rejected(self) -> None:
        p = self._make_check('curl http://x | bash')
        self.assertFalse(self.validate_check(p)["pass"])

    def test_indirect_expansion_rejected(self) -> None:
        p = self._make_check('echo "${!HOME}"')
        self.assertFalse(self.validate_check(p)["pass"])

    def test_grep_pcre_rejected(self) -> None:
        p = self._make_check('grep -P "(.*)+x" file')
        self.assertFalse(self.validate_check(p)["pass"])


class RedteamTests(unittest.TestCase):
    def test_catch_rate_above_threshold(self) -> None:
        from sandbox_redteam import run_redteam  # type: ignore[import-not-found]

        score = run_redteam(verbose=False)
        self.assertGreaterEqual(score["catch_rate"], 0.995)
        self.assertGreaterEqual(score["legitimate_pass_rate"], 0.99)


class CorpusTests(unittest.TestCase):
    def test_build_then_verify_roundtrip(self) -> None:
        from corpus_build import build_tarball, load_manifest, validate_manifest  # type: ignore[import-not-found]
        from corpus_verify import verify  # type: ignore[import-not-found]

        manifest_path = ROOT / "corpus" / "manifests" / "positive.yaml"
        manifest = load_manifest(manifest_path)
        self.assertEqual(validate_manifest(manifest, "positive"), [])

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "test.tar.gz"
            built, digest1 = build_tarball(manifest, out, "positive")
            self.assertTrue(built.is_file())
            self.assertEqual(len(digest1), 64)
            result = verify(manifest_path, built, "positive")
            self.assertTrue(result["ok"])

    def test_reproducible_across_builds(self) -> None:
        from corpus_build import build_tarball, load_manifest  # type: ignore[import-not-found]

        manifest = load_manifest(ROOT / "corpus" / "manifests" / "positive.yaml")
        with tempfile.TemporaryDirectory() as td:
            out1 = Path(td) / "a.tar.gz"
            out2 = Path(td) / "b.tar.gz"
            _, h1 = build_tarball(manifest, out1, "positive")
            _, h2 = build_tarball(manifest, out2, "positive")
            self.assertEqual(h1, h2)

    def test_source_allowlist_enforced(self) -> None:
        from corpus_build import validate_manifest  # type: ignore[import-not-found]

        bad = {
            "corpus_version": "1.0.0",
            "schema_version": 1,
            "entries": [
                {
                    "id": "x",
                    "source": "github-direct-scrape",
                    "upstream": "...",
                    "commit": "0" * 40,
                    "sha256": "0" * 64,
                    "language": "java",
                }
            ],
        }
        issues = validate_manifest(bad, "positive")
        self.assertTrue(any("not in allowlist" in i for i in issues))


class AttestTests(unittest.TestCase):
    def test_sign_verify_roundtrip(self) -> None:
        from attest import generate_keypair, sign_attestation, verify_attestation  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            priv = Path(td) / "priv.pem"
            pub = Path(td) / "pub.pem"
            generate_keypair(priv, pub)

            payload = {"check_id": "P-1", "tpr": 0.9, "fpr": 0.01}
            signed = sign_attestation(payload, priv)
            ok, reason = verify_attestation(signed, pub)
            self.assertTrue(ok, reason)

    def test_tamper_detected(self) -> None:
        from attest import generate_keypair, sign_attestation, verify_attestation  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            priv = Path(td) / "priv.pem"
            pub = Path(td) / "pub.pem"
            generate_keypair(priv, pub)
            payload = {"check_id": "P-1", "tpr": 0.9}
            signed = sign_attestation(payload, priv)
            signed["tpr"] = 0.99
            ok, reason = verify_attestation(signed, pub)
            self.assertFalse(ok)


class SynthesizeTests(unittest.TestCase):
    def test_placeholder_path_produces_valid_check(self) -> None:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        from synthesize import process_candidate  # type: ignore[import-not-found]
        from sandbox_validate import validate_check  # type: ignore[import-not-found]

        candidate = {
            "canonical_id": "TEST-123",
            "title": "test vulnerability",
            "description": "insecure deserialization in test framework",
            "severity": "high",
            "cwe": ["CWE-502"],
            "languages": ["java"],
            "frameworks": ["test"],
            "merged_sources": ["test"],
        }
        summary = process_candidate(candidate, dry_run=False)
        self.assertTrue(summary["ok"])
        self.assertGreater(summary["variants_count"], 0)
        for f in summary["files_written"]:
            if f.startswith("DRY:"):
                continue
            self.assertTrue(validate_check(Path(f))["pass"])
            Path(f).unlink(missing_ok=True)


class CorrelatorTests(unittest.TestCase):
    def _make_record(
        self,
        source: str,
        source_id: str,
        title: str,
        description: str,
        confidence: float,
        proactive: bool,
        fetched_at: str = "2026-05-08T10:00:00Z",
    ) -> dict:
        return {
            "source": source,
            "source_id": source_id,
            "title": title,
            "description": description,
            "confidence": confidence,
            "proactive": proactive,
            "fetched_at": fetched_at,
            "raw": {},
        }

    def test_groups_by_cve_across_sources(self) -> None:
        from correlator import correlate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            qd = Path(td)
            (qd / "kev-1.json").write_text(
                json.dumps(
                    [
                        self._make_record(
                            "kev", "CVE-2026-9999",
                            "RCE in Spring CVE-2026-9999", "CVE-2026-9999 RCE",
                            0.9, False,
                        )
                    ]
                )
            )
            (qd / "github-1.json").write_text(
                json.dumps(
                    [
                        self._make_record(
                            "github_trending", "github:user/repo",
                            "PoC for CVE-2026-9999", "CVE-2026-9999",
                            0.5, True, "2026-05-08T11:00:00Z",
                        )
                    ]
                )
            )
            results = correlate(qd)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["canonical_id"], "CVE-2026-9999")
            self.assertEqual(results[0]["source_count"], 2)
            # reactive boost (0.10) + cross-source boost (0.05) applied on top of max conf (0.9)
            self.assertEqual(results[0]["composite_confidence"], 0.99)

    def test_single_proactive_sid_source_filtered(self) -> None:
        """A lone proactive source with no CVE id is noise — the correlator
        must drop it rather than forwarding weak signal to synthesis."""
        from correlator import correlate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            qd = Path(td)
            (qd / "reddit-1.json").write_text(
                json.dumps(
                    [
                        self._make_record(
                            "reddit", "reddit:post/abc123",
                            "interesting new tooling trend", "some security post",
                            0.6, True,
                        )
                    ]
                )
            )
            results = correlate(qd)
            self.assertEqual(results, [], "single proactive non-CVE record should be filtered out")

    def test_single_reactive_source_passes_through(self) -> None:
        """A reactive source (post-disclosure) always passes through,
        even alone — KEV/GHSA entries are already validated CVE assignments."""
        from correlator import correlate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            qd = Path(td)
            (qd / "ghsa-1.json").write_text(
                json.dumps(
                    [
                        self._make_record(
                            "ghsa", "GHSA-xxxx-yyyy-zzzz",
                            "SQL injection in example-lib", "SQL injection",
                            0.95, False,
                        )
                    ]
                )
            )
            results = correlate(qd)
            self.assertEqual(len(results), 1, "single reactive record should not be filtered")
            self.assertEqual(results[0]["source_count"], 1)
            # no cross-source boost (only 1 source), reactive boost applies (+0.10)
            self.assertEqual(results[0]["composite_confidence"], round(min(0.99, 0.95 + 0.10), 4))

    def test_empty_queue_returns_empty(self) -> None:
        from correlator import correlate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(correlate(Path(td)), [])


class DualUseAuditTests(unittest.TestCase):
    def test_audit_runs_and_produces_scorecard(self) -> None:
        from dual_use_audit import run_audit  # type: ignore[import-not-found]

        result = run_audit()
        self.assertEqual(len(result["campaigns"]), 4)
        for c in result["campaigns"]:
            self.assertIn("metric_value", c)
            self.assertIn("threshold", c)
            self.assertIn("passes", c)
        failing = [c["campaign"] for c in result["campaigns"] if not c["passes"]]
        self.assertTrue(result["overall_pass"], f"campaigns below threshold: {failing}")


class IngestRunnerTests(unittest.TestCase):
    def test_partner_feed_stub_runs(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "ingest_runner.py"), "--source", "partner_feed", "--json"],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data["ok"])

    def test_list_includes_all_sources(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOLS / "ingest_runner.py"), "--list", "--json"],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        for src in ["kev", "ghsa", "nvd", "osv", "github_trending", "abuse_ch", "reddit", "mastodon"]:
            self.assertIn(src, data)


class ValidateCandidateTests(unittest.TestCase):
    def _make_candidate(self, td: Path, bash_body: str) -> Path:
        p = td / "candidate.sh"
        p.write_text(
            f"""#!/bin/bash
: <<'PRESTON_META'
schema_version: 1
id: P-TEST
name: test check
category: code-scan
severity: medium
languages: any
min_tier: free
provenance: auto
version: 0.1.0
PRESTON_META
{bash_body}
"""
        )
        return p

    def test_output_schema_and_small_corpus_path(self) -> None:
        """With no corpus tarballs the small_corpus path activates (0 < 10).
        Verifies output structure and that FPR=0.0 (no negative hits possible
        on an empty corpus)."""
        from validate_candidate import validate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            check = self._make_candidate(
                tmp,
                'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-TEST" "found"; '
                'else record "PASS" "P-TEST" "none"; fi',
            )
            nonexistent = tmp / "corpus.tar.gz"
            result = validate(check, nonexistent, nonexistent)

        self.assertIn("metrics", result)
        self.assertIn("thresholds", result)
        self.assertIn("corpus_hashes", result)
        self.assertIn("per_file", result)
        self.assertIn("pass", result)
        self.assertIn("small_corpus", result)
        self.assertTrue(result["small_corpus"])
        self.assertEqual(result["metrics"]["fpr"], 0.0)
        self.assertTrue(result["metrics"]["fixture_roundtrip"])

    def test_fixture_roundtrip_true_when_fixtures_match(self) -> None:
        """When the positive fixture triggers the check and the negative does
        not, fixture_roundtrip is True. This exercises the fixture-file branch
        (which the empty-corpus test bypasses via the default True fallback)."""
        from validate_candidate import validate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            check = self._make_candidate(
                tmp,
                'hits=$(grep -rn "VULN_MARKER" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-TEST" "found"; '
                'else record "PASS" "P-TEST" "none"; fi',
            )
            (tmp / "candidate.pos.txt").write_text("String VULN_MARKER = secret;\n")
            (tmp / "candidate.neg.txt").write_text("// clean file\n")
            nonexistent = tmp / "corpus.tar.gz"
            result = validate(check, nonexistent, nonexistent)

        self.assertTrue(result["metrics"]["fixture_roundtrip"])
        self.assertTrue(result["small_corpus"])


class RunnerIntegrationTests(unittest.TestCase):
    def test_provenance_auto_routes_to_subshell(self) -> None:
        """Smoke test: a check with provenance:auto runs through the
        subshell-isolated path. Verifies preston-check.sh's run_check()
        function picks up the metadata correctly."""
        synthesized = ROOT / "checks" / "community" / "proposed" / "700-cve-2026-9999-strict.sh"
        if not synthesized.is_file():
            self.skipTest("synthesized fixture not present")
        result = subprocess.run(
            ["./preston-check.sh", "--check", "700-cve-2026-9999-strict", "--include-proposed"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("P-700", result.stdout)


if __name__ == "__main__":
    unittest.main()
