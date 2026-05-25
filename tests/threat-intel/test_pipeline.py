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
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


class SandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        from sandbox_validate import validate_check  # type: ignore[import-not-found]

        self.validate_check = validate_check

    def _make_check(self, body: str, provenance: str = "auto") -> Path:
        td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, td, True)
        p = Path(td) / "test.sh"
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

    def test_awk_system_escape_rejected(self) -> None:
        p = self._make_check("awk 'BEGIN{system(\"id\")}' /dev/null")
        self.assertFalse(self.validate_check(p)["pass"])

    def test_output_redirect_to_file_rejected(self) -> None:
        p = self._make_check('printf "%s" payload > /tmp/out')
        self.assertFalse(self.validate_check(p)["pass"])

    def test_output_redirect_nospace_rejected(self) -> None:
        """Redirect without a space between > and target must also be caught."""
        p = self._make_check('printf "%s" payload>/tmp/out')
        self.assertFalse(self.validate_check(p)["pass"])

    def test_sed_e_flag_rejected(self) -> None:
        """sed s///e executes the replacement string as a shell command."""
        p = self._make_check("sed 's/.*/id/e' /dev/null")
        self.assertFalse(self.validate_check(p)["pass"])

    def test_awk_f_flag_rejected(self) -> None:
        """awk -f loads the program from a file, bypassing inline program-text inspection."""
        p = self._make_check("awk -f /proc/self/environ /dev/null")
        self.assertFalse(self.validate_check(p)["pass"])

    def test_awk_variable_program_rejected(self) -> None:
        """awk with a variable as the program text cannot have its content verified."""
        p = self._make_check('PRG=\'BEGIN{system("id")}\'\nawk "$PRG" /dev/null')
        self.assertFalse(self.validate_check(p)["pass"])

    def test_redirect_in_grep_string_not_flagged(self) -> None:
        """A > character inside a grep pattern string must not trigger the redirect rule."""
        p = self._make_check(
            'hits=$(grep -rn "size > 0" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
            'record "PASS" "P-TEST" "ok"'
        )
        self.assertTrue(self.validate_check(p)["pass"])

    def test_awk_herestring_rejected(self) -> None:
        """awk program supplied via here-string cannot be statically inspected and must be blocked."""
        p = self._make_check("awk <<<'BEGIN{system(\"id\")}' /dev/null")
        self.assertFalse(self.validate_check(p)["pass"])

    def test_redirect_after_unclosed_string_still_caught(self) -> None:
        """An unclosed single-quote must not cause _strip_string_literals to swallow
        all subsequent content, rendering the redirect prohibition blind to what follows."""
        # echo 'unclosed starts a string that never closes; the redirect on the
        # next line must still be visible to the pattern checker.
        body = "echo 'unclosed\n" + 'printf "%s" data > /tmp/evil'
        p = self._make_check(body)
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

    def test_tamper_detected_in_verify(self) -> None:
        from corpus_build import build_tarball, load_manifest  # type: ignore[import-not-found]
        from corpus_verify import verify  # type: ignore[import-not-found]

        manifest_path = ROOT / "corpus" / "manifests" / "positive.yaml"
        manifest = load_manifest(manifest_path)
        with tempfile.TemporaryDirectory() as td:
            tarball = Path(td) / "positive.tar.gz"
            build_tarball(manifest, tarball, "positive")
            # flip one byte to simulate post-build tampering
            raw = bytearray(tarball.read_bytes())
            raw[-1] ^= 0xFF
            tarball.write_bytes(bytes(raw))
            result = verify(manifest_path, tarball, "positive")
        self.assertFalse(result["ok"])
        self.assertFalse(result["match_rebuild"])

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

    def test_wrong_key_rejected(self) -> None:
        """An attestation signed with key A must be rejected when verified against key B."""
        from attest import generate_keypair, sign_attestation, verify_attestation  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            priv_a = Path(td) / "a.pem"
            pub_a = Path(td) / "a.pub.pem"
            priv_b = Path(td) / "b.pem"
            pub_b = Path(td) / "b.pub.pem"
            generate_keypair(priv_a, pub_a)
            generate_keypair(priv_b, pub_b)
            payload = {"check_id": "P-1", "tpr": 0.9}
            signed = sign_attestation(payload, priv_a)
            ok, _ = verify_attestation(signed, pub_b)
            self.assertFalse(ok)


class SynthesizeTests(unittest.TestCase):
    def test_placeholder_path_produces_valid_check(self) -> None:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        import synthesize  # type: ignore[import-not-found]
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
        with tempfile.TemporaryDirectory() as td:
            candidates_dir = Path(td) / "candidates"
            candidates_dir.mkdir()
            with patch.object(synthesize, "CANDIDATES_DIR", candidates_dir):
                summary = synthesize.process_candidate(candidate, dry_run=False)
            self.assertTrue(summary["ok"])
            self.assertGreater(summary["variants_count"], 0)
            for f in summary["files_written"]:
                if f.startswith("DRY:"):
                    continue
                self.assertTrue(validate_check(Path(f))["pass"])


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
            self.assertEqual(results[0]["source_type_count"], 2)
            self.assertEqual(results[0]["record_count"], 2)
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
            self.assertEqual(results[0]["source_type_count"], 1)
            self.assertEqual(results[0]["record_count"], 1)
            # no cross-source boost (only 1 source), reactive boost applies (+0.10)
            self.assertEqual(results[0]["composite_confidence"], round(min(0.99, 0.95 + 0.10), 4))

    def test_empty_queue_returns_empty(self) -> None:
        from correlator import correlate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(correlate(Path(td)), [])

    def test_single_proactive_cve_source_filtered(self) -> None:
        """A lone proactive source is now filtered regardless of key_kind — CVE
        mentions on Reddit/Mastodon with no corroboration are noise."""
        from correlator import correlate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            qd = Path(td)
            (qd / "reddit-cve.json").write_text(
                json.dumps(
                    [
                        self._make_record(
                            "reddit", "CVE-2026-9999",
                            "PoC for CVE-2026-9999 trending", "CVE-2026-9999",
                            0.6, True,
                        )
                    ]
                )
            )
            results = correlate(qd)
            self.assertEqual(results, [], "single proactive CVE-keyed record should be filtered")


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
        for src in [
            "kev", "ghsa", "nvd", "osv",
            "github_trending", "abuse_ch", "reddit", "mastodon",
            "mailing_list", "conference_zdi", "newsletter", "rss_feeds", "partner_feed",
        ]:
            self.assertIn(src, data, f"source '{src}' missing from SOURCES registry")


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
        # stability=0.0 with empty corpus (no positive entries to perturb) → gate fails
        self.assertFalse(result["pass"])

    def test_crash_before_record_returns_crash_status(self) -> None:
        """A check script that exits non-zero before emitting any RECORD line
        must return status=CRASH, not be silently counted as a non-fire."""
        from validate_candidate import _run_bash_against_file  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            target_dir = Path(td) / "target"
            target_dir.mkdir()
            (target_dir / "sample.txt").write_text("content\n")
            # /bin/false exits immediately with code 1; set -euo pipefail causes
            # the whole runner to abort before the RECORD line is reached.
            crashed_body = '/bin/false\nrecord "FAIL" "P-TEST" "should not reach"'
            fired, status = _run_bash_against_file(crashed_body, target_dir)

        self.assertFalse(fired)
        self.assertEqual(status, "CRASH")

    def test_fixture_roundtrip_false_when_check_fires_on_negative(self) -> None:
        """When the check fires on the negative fixture, fixture_roundtrip must be False
        and the overall gate must fail — a check that can't discriminate clean from
        vulnerable code must not be promoted."""
        from validate_candidate import validate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # This check always fires (grep matches any non-empty file).
            check = self._make_candidate(
                tmp,
                'hits=$(grep -rn "." "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-TEST" "found"; '
                'else record "PASS" "P-TEST" "none"; fi',
            )
            (tmp / "candidate.pos.txt").write_text("VULN_MARKER content\n")
            (tmp / "candidate.neg.txt").write_text("// clean file\n")
            nonexistent = tmp / "corpus.tar.gz"
            result = validate(check, nonexistent, nonexistent)

        # Fires on both pos and neg fixtures → roundtrip fails
        self.assertFalse(result["metrics"]["fixture_roundtrip"])
        self.assertFalse(result["pass"])

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
        # stability gate still fails (no positive corpus entries to run perturbed pass against)
        self.assertFalse(result["pass"])


class AdversarialLoopTests(unittest.TestCase):
    def _make_check(self, td: Path, bash_body: str) -> Path:
        p = td / "adv_candidate.sh"
        p.write_text(
            f"""#!/bin/bash
: <<'PRESTON_META'
schema_version: 1
id: P-ADV
name: adversarial test check
provenance: auto
version: 0.1.0
PRESTON_META
{bash_body}
"""
        )
        return p

    def test_empty_corpus_passes_with_zero_evasions(self) -> None:
        """With an empty positive corpus directory there are no samples to
        evade. The loop completes with successful_evasions=0 and passes=True."""
        from adversarial_loop import run_adversarial  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            check = self._make_check(
                tmp,
                'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-ADV" "found"; '
                'else record "PASS" "P-ADV" "none"; fi',
            )
            empty_corpus = tmp / "positive"
            empty_corpus.mkdir()
            result = run_adversarial(check, empty_corpus)

        self.assertTrue(result["ok"])
        self.assertEqual(result["successful_evasions"], 0)
        self.assertTrue(result["passes"])
        self.assertIn("transcript_hash", result)

    def test_model_monoculture_rejected(self) -> None:
        """Using the same provider for both synth and adversarial models
        is refused — model diversity is a hard requirement."""
        from adversarial_loop import run_adversarial  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            check = self._make_check(tmp, 'record "PASS" "P-ADV" "ok"')
            empty_corpus = tmp / "positive"
            empty_corpus.mkdir()
            result = run_adversarial(
                check,
                empty_corpus,
                synth_model="claude-opus-4-7",
                adv_model="claude-haiku-4-5-20251001",
            )

        self.assertFalse(result["ok"])
        self.assertIn("monoculture", result.get("reason", ""))

    def test_unknown_provider_monoculture_rejected(self) -> None:
        """Unrecognised model names (not claude* or gpt*) must be refused even when
        the two models are from different unknown providers — diversity cannot be
        verified without a recognised provider name."""
        from adversarial_loop import run_adversarial  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            check = self._make_check(tmp, 'record "PASS" "P-ADV" "ok"')
            empty_corpus = tmp / "positive"
            empty_corpus.mkdir()
            result = run_adversarial(
                check,
                empty_corpus,
                synth_model="mistral-large",
                adv_model="mistral-medium",
            )

        self.assertFalse(result["ok"])
        self.assertIn("monoculture", result.get("reason", ""))

    def test_o_series_openai_models_recognised(self) -> None:
        """o1, o3, o4-mini must be recognised as OpenAI — pairing them with claude
        satisfies the provider diversity requirement."""
        from adversarial_loop import run_adversarial  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            check = self._make_check(
                tmp,
                'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-ADV" "found"; '
                'else record "PASS" "P-ADV" "none"; fi',
            )
            empty_corpus = tmp / "positive"
            empty_corpus.mkdir()
            result = run_adversarial(
                check,
                empty_corpus,
                synth_model="claude-haiku-4-5-20251001",
                adv_model="o3",
            )

        self.assertTrue(result["ok"], f"o3 should be recognised as openai: {result.get('reason')}")
        self.assertTrue(result["passes"])


class TelemetryQuorumTests(unittest.TestCase):
    def test_quorum_passes_above_threshold(self) -> None:
        from telemetry_aggregate import _quorum_pass  # type: ignore[import-not-found]

        self.assertTrue(_quorum_pass(distinct_fingerprints=15, days_span=20, n=10, days=14))

    def test_quorum_fails_too_few_installs(self) -> None:
        from telemetry_aggregate import _quorum_pass  # type: ignore[import-not-found]

        self.assertFalse(_quorum_pass(distinct_fingerprints=5, days_span=20, n=10, days=14))

    def test_quorum_fails_too_short_window(self) -> None:
        from telemetry_aggregate import _quorum_pass  # type: ignore[import-not-found]

        self.assertFalse(_quorum_pass(distinct_fingerprints=15, days_span=7, n=10, days=14))

    def test_quorum_passes_exactly_at_boundary(self) -> None:
        """_quorum_pass uses >=, so exactly meeting n and days is sufficient."""
        from telemetry_aggregate import _quorum_pass  # type: ignore[import-not-found]

        self.assertTrue(_quorum_pass(distinct_fingerprints=10, days_span=14, n=10, days=14))


class OrchestrateTests(unittest.TestCase):
    def _make_check(self, td: Path, bash_body: str, check_id: str = "700") -> Path:
        p = td / f"{check_id}-cve-test-strict.sh"
        p.write_text(
            f"""#!/bin/bash
: <<'PRESTON_META'
schema_version: 1
id: P-{check_id}
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

    def test_build_attestation_schema(self) -> None:
        """_build_attestation is pure; all expected top-level keys are present."""
        import orchestrate  # type: ignore[import-not-found]

        candidate = {
            "canonical_id": "CVE-2026-9999",
            "merged_sources": ["kev"],
            "first_seen": "2026-01-01T00:00:00Z",
        }
        sandbox = {"pass": True, "validator_version": "0.2.0", "reasons": []}
        validate_res = {
            "pass": True,
            "metrics": {"tpr": 0.9, "fpr": 0.01, "stability": 0.95},
            "corpus_hashes": {"positive": "abc", "negative": "def"},
        }
        adversarial = {
            "passes": True,
            "rounds": 3,
            "transcript_hash": "abc123",
            "synth_model": "claude-haiku-4-5-20251001",
            "adv_model": "openai/gpt-4o",
        }
        att = orchestrate._build_attestation(candidate, sandbox, validate_res, adversarial, "700-cve-2026-9999-strict")

        for key in ("attestation_version", "check_id", "source", "synthesis", "sandbox", "validation", "adversarial", "merged_at"):
            self.assertIn(key, att)
        self.assertEqual(att["check_id"], "700-cve-2026-9999-strict")
        self.assertEqual(att["source"]["id"], "CVE-2026-9999")
        self.assertTrue(att["sandbox"]["pass"])
        self.assertEqual(att["validation"]["tpr"], 0.9)
        self.assertTrue(att["adversarial"]["passes"])

    def test_process_candidate_rejected_at_sandbox(self) -> None:
        """eval in check body → sandbox rejects → outcome rejected:sandbox and copy appears in retry queue."""
        import orchestrate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            retry_dir = tmp / "retry"
            check = self._make_check(tmp, 'eval "ls"')
            nonexistent = tmp / "corpus.tar.gz"
            with patch.object(orchestrate, "RETRY_QUEUE", retry_dir):
                summary = orchestrate.process_candidate(
                    check,
                    {"canonical_id": "CVE-2026-9999"},
                    nonexistent,
                    nonexistent,
                    dry_run=True,
                )
            self.assertEqual(summary["outcome"], "rejected:sandbox")
            self.assertFalse(summary["sandbox"].get("pass"))
            self.assertTrue((retry_dir / check.name).is_file())

    def test_process_candidate_rejected_at_validate(self) -> None:
        """Legitimate check passes sandbox but fails validate (stability=0 with empty corpus)."""
        import orchestrate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            retry_dir = tmp / "retry"
            check = self._make_check(
                tmp,
                'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-700" "found"; '
                'else record "PASS" "P-700" "none"; fi',
            )
            nonexistent = tmp / "corpus.tar.gz"
            with patch.object(orchestrate, "RETRY_QUEUE", retry_dir):
                summary = orchestrate.process_candidate(
                    check,
                    {"canonical_id": "CVE-2026-9999"},
                    nonexistent,
                    nonexistent,
                    dry_run=True,
                )
        self.assertEqual(summary["outcome"], "rejected:validate")

    def test_process_candidate_rejected_at_adversarial(self) -> None:
        """Sandbox and validate stubbed to pass, adversarial stubbed to fail → rejected:adversarial."""
        import orchestrate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            retry_dir = tmp / "retry"
            check = self._make_check(
                tmp,
                'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-700" "found"; '
                'else record "PASS" "P-700" "none"; fi',
            )
            nonexistent = tmp / "corpus.tar.gz"
            with (
                patch.object(orchestrate, "_gate_sandbox", return_value={"pass": True, "validator_version": "0.2.0", "reasons": []}),
                patch.object(orchestrate, "_gate_validate", return_value={"pass": True, "metrics": {"tpr": 0.9, "fpr": 0.01, "stability": 0.95}, "corpus_hashes": {}}),
                patch.object(orchestrate, "_gate_adversarial", return_value={"passes": False, "reason": "evasion succeeded"}),
                patch.object(orchestrate, "RETRY_QUEUE", retry_dir),
            ):
                summary = orchestrate.process_candidate(
                    check,
                    {"canonical_id": "CVE-2026-9999"},
                    nonexistent,
                    nonexistent,
                    dry_run=True,
                )
            self.assertEqual(summary["outcome"], "rejected:adversarial")

    def test_dry_run_does_not_move_file(self) -> None:
        """With all gates stubbed to pass, dry_run=True yields would-promote without moving the file."""
        import orchestrate  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            att_dir = tmp / "attestations"
            att_dir.mkdir()
            check = self._make_check(
                tmp,
                'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then record "FAIL" "P-700" "found"; '
                'else record "PASS" "P-700" "none"; fi',
            )
            nonexistent = tmp / "corpus.tar.gz"
            with (
                patch.object(orchestrate, "_gate_sandbox", return_value={"pass": True, "validator_version": "0.2.0", "reasons": []}),
                patch.object(orchestrate, "_gate_validate", return_value={"pass": True, "metrics": {"tpr": 0.9, "fpr": 0.01, "stability": 0.95}, "corpus_hashes": {}}),
                patch.object(orchestrate, "_gate_adversarial", return_value={"passes": True, "rounds": 1, "transcript_hash": "abc", "synth_model": "claude-haiku-4-5-20251001", "adv_model": "openai/gpt-4o"}),
                patch.object(orchestrate, "ATTESTATIONS", att_dir),
            ):
                summary = orchestrate.process_candidate(
                    check,
                    {"canonical_id": "CVE-2026-9999"},
                    nonexistent,
                    nonexistent,
                    dry_run=True,
                )
            self.assertEqual(summary["outcome"], "would-promote")
            self.assertTrue(check.is_file(), "file must remain in place during dry run")


class DriftDetectTests(unittest.TestCase):
    def _make_catalog_check(self, catalog_dir: Path) -> Path:
        check = catalog_dir / "700-cve-decay-test.sh"
        check.write_text(
            "#!/bin/bash\n"
            ": <<'PRESTON_META'\n"
            "schema_version: 1\n"
            "id: P-700\n"
            "name: decay test check\n"
            "category: code-scan\n"
            "severity: medium\n"
            "languages: any\n"
            "min_tier: free\n"
            "provenance: auto\n"
            "version: 0.1.0\n"
            "PRESTON_META\n"
            'hits=$(grep -rn "password" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
            'if [[ -n "$hits" ]]; then record "FAIL" "P-700" "found"; '
            'else record "PASS" "P-700" "none"; fi\n'
        )
        return check

    def test_empty_catalog_produces_no_flags(self) -> None:
        """With no check files in CATALOG_DIRS the flagged lists are empty."""
        import drift_detect  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            empty_catalog = tmp / "empty"
            empty_catalog.mkdir()
            baseline_file = tmp / "baseline.json"
            flagged_file = tmp / "flagged.json"
            with (
                patch.object(drift_detect, "CATALOG_DIRS", [empty_catalog]),
                patch.object(drift_detect, "BASELINE_FILE", baseline_file),
                patch.object(drift_detect, "FLAGGED_FILE", flagged_file),
            ):
                result = drift_detect.detect_drift(
                    tmp / "pos.tar.gz", tmp / "neg.tar.gz", 0.10, 0.02
                )
        self.assertEqual(result["flagged"]["decayed"], [])
        self.assertEqual(result["flagged"]["noisy"], [])
        self.assertEqual(result["flagged"]["checks_evaluated"], 0)

    def test_decay_flagged_when_tpr_drops_below_threshold(self) -> None:
        """Seeding baseline with TPR=0.9 then re-running against empty corpus (TPR=0.0) flags decay."""
        import drift_detect  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            catalog_dir = tmp / "catalog"
            catalog_dir.mkdir()
            baseline_file = tmp / "baseline.json"
            flagged_file = tmp / "flagged.json"
            check = self._make_catalog_check(catalog_dir)
            baseline_file.write_text(
                json.dumps({check.name: {"tpr": 0.9, "fpr": 0.01, "stability": 0.95}})
            )
            with (
                patch.object(drift_detect, "CATALOG_DIRS", [catalog_dir]),
                patch.object(drift_detect, "BASELINE_FILE", baseline_file),
                patch.object(drift_detect, "FLAGGED_FILE", flagged_file),
            ):
                result = drift_detect.detect_drift(
                    tmp / "pos.tar.gz", tmp / "neg.tar.gz", 0.10, 0.02
                )
        self.assertEqual(len(result["flagged"]["decayed"]), 1)
        self.assertEqual(result["flagged"]["decayed"][0]["check"], check.name)

    def test_noisy_flagged_when_fpr_rises_above_threshold(self) -> None:
        """Seeding baseline with FPR=0.01 then mock-returning FPR=0.05 flags the check as noisy."""
        import drift_detect  # type: ignore[import-not-found]

        mock_result = {
            "metrics": {"tpr": 0.9, "fpr": 0.05, "stability": 0.9},
            "pass": False,
        }
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            catalog_dir = tmp / "catalog"
            catalog_dir.mkdir()
            baseline_file = tmp / "baseline.json"
            flagged_file = tmp / "flagged.json"
            check = catalog_dir / "700-cve-noisy-test.sh"
            check.write_text("#!/bin/bash\nrecord PASS P-700 ok\n")
            baseline_file.write_text(json.dumps({check.name: {"tpr": 0.9, "fpr": 0.01}}))
            with (
                patch.object(drift_detect, "CATALOG_DIRS", [catalog_dir]),
                patch.object(drift_detect, "BASELINE_FILE", baseline_file),
                patch.object(drift_detect, "FLAGGED_FILE", flagged_file),
                patch.object(drift_detect, "validate", return_value=mock_result),
            ):
                result = drift_detect.detect_drift(
                    tmp / "pos.tar.gz", tmp / "neg.tar.gz", 0.10, 0.02
                )
        self.assertEqual(len(result["flagged"]["noisy"]), 1)
        self.assertEqual(result["flagged"]["noisy"][0]["check"], check.name)

    def test_write_report_creates_markdown_file(self) -> None:
        """write_report produces a markdown file in the target directory."""
        import drift_detect  # type: ignore[import-not-found]

        result = {
            "summary": [{"check": "foo.sh", "tpr": 0.5, "fpr": 0.01, "delta_tpr": None, "delta_fpr": None}],
            "flagged": {"checks_evaluated": 1, "decayed": [], "noisy": [], "ts": "2026-05-25T00:00:00Z"},
        }
        with tempfile.TemporaryDirectory() as td:
            report_path = drift_detect.write_report(result, Path(td))
            self.assertTrue(report_path.is_file())
            content = report_path.read_text()
        self.assertIn("Drift Report", content)
        self.assertIn("None.", content)


class NotifyPromotionTests(unittest.TestCase):
    def _promoted_summary(self, outcome: str = "promoted") -> dict:
        return {
            "ts": "2026-05-25T12:00:00Z",
            "automerge_enabled": True,
            "dry_run": False,
            "summaries": [
                {
                    "outcome": outcome,
                    "canonical_id": "CVE-2026-9999",
                    "check_id": "700",
                    "validate": {"metrics": {"tpr": 0.9, "fpr": 0.01, "stability": 0.95}},
                    "adversarial": {"passes": True},
                }
            ],
        }

    def test_empty_summary_returns_empty_strings(self) -> None:
        from notify_promotion import render_promotion_email  # type: ignore[import-not-found]

        summary = {"ts": "2026-05-25T12:00:00Z", "summaries": [
            {"outcome": "rejected:sandbox", "canonical_id": "CVE-2026-9999", "check_id": "700"},
        ]}
        subject, text, html = render_promotion_email(summary, "")
        self.assertEqual(subject, "")
        self.assertEqual(text, "")
        self.assertEqual(html, "")

    def test_single_cve_subject(self) -> None:
        from notify_promotion import render_promotion_email  # type: ignore[import-not-found]

        subject, _, _ = render_promotion_email(self._promoted_summary(), "https://github.com/foo/bar/pull/42")
        self.assertIn("CVE-2026-9999", subject)
        self.assertIn("1 new check", subject)

    def test_would_promote_included_in_active(self) -> None:
        """outcome=would-promote counts as active; subject must not be empty."""
        from notify_promotion import render_promotion_email  # type: ignore[import-not-found]

        subject, _, _ = render_promotion_email(
            self._promoted_summary("would-promote"),
            "https://github.com/foo/bar/pull/42",
        )
        self.assertNotEqual(subject, "")
        self.assertIn("CVE-2026-9999", subject)

    def test_compare_url_renders_action_required(self) -> None:
        from notify_promotion import render_promotion_email  # type: ignore[import-not-found]

        compare_url = "https://github.com/foo/bar/compare/master...branch?expand=1"
        _, text, _ = render_promotion_email(self._promoted_summary(), compare_url)
        self.assertIn("ACTION REQUIRED", text)

    def test_normal_pr_url_no_action_required(self) -> None:
        from notify_promotion import render_promotion_email  # type: ignore[import-not-found]

        _, text, _ = render_promotion_email(
            self._promoted_summary(), "https://github.com/foo/bar/pull/42"
        )
        self.assertNotIn("ACTION REQUIRED", text)
        self.assertIn("auto-merge queued", text)

    def test_explain_metrics_tpr_zero_uses_proxy_message(self) -> None:
        from notify_promotion import _explain_metrics  # type: ignore[import-not-found]

        result = _explain_metrics(0.0, 0.01, 0.95)
        self.assertIn("proxy", result)

    def test_explain_metrics_normal_values(self) -> None:
        from notify_promotion import _explain_metrics  # type: ignore[import-not-found]

        result = _explain_metrics(0.9, 0.01, 0.95)
        self.assertIn("90%", result)
        self.assertIn("1%", result)
        self.assertIn("95%", result)

    def test_is_compare_url(self) -> None:
        from notify_promotion import _is_compare_url  # type: ignore[import-not-found]

        self.assertTrue(_is_compare_url("https://github.com/foo/bar/compare/master...branch?expand=1"))
        self.assertFalse(_is_compare_url("https://github.com/foo/bar/pull/42"))
        self.assertFalse(_is_compare_url(""))

    def _write_accepted_check(self, accepted_dir: Path, stem: str) -> Path:
        check = accepted_dir / f"{stem}.sh"
        check.write_text(
            "#!/bin/bash\n"
            ": <<'PRESTON_META'\n"
            "schema_version: 1\n"
            "id: P-700\n"
            "name: CVE-2026-9999 strict detection (strict)\n"
            "severity: high\n"
            "cwe: CWE-502\n"
            "frameworks: kev,ghsa\n"
            "PRESTON_META\n"
            'record "PASS" "P-700" "test"\n'
        )
        return check

    def test_read_check_meta_finds_full_stem(self) -> None:
        """_read_check_meta must read metadata when given the full filename stem."""
        import notify_promotion  # type: ignore[import-not-found]
        from notify_promotion import _read_check_meta  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            accepted_dir = tmp / "checks" / "community" / "accepted"
            accepted_dir.mkdir(parents=True)
            self._write_accepted_check(accepted_dir, "700-cve-2026-9999-strict")
            with patch.object(notify_promotion, "ROOT", tmp):
                meta = _read_check_meta("700-cve-2026-9999-strict")

        self.assertEqual(meta.get("name"), "CVE-2026-9999 strict detection (strict)")
        self.assertEqual(meta.get("severity"), "high")
        self.assertEqual(meta.get("cwe"), "CWE-502")
        self.assertEqual(meta.get("frameworks"), "kev,ghsa")

    def test_read_check_meta_prefix_glob_fallback(self) -> None:
        """_read_check_meta must fall back to prefix glob when given a bare numeric ID."""
        import notify_promotion  # type: ignore[import-not-found]
        from notify_promotion import _read_check_meta  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            accepted_dir = tmp / "checks" / "community" / "accepted"
            accepted_dir.mkdir(parents=True)
            self._write_accepted_check(accepted_dir, "700-cve-2026-9999-strict")
            with patch.object(notify_promotion, "ROOT", tmp):
                meta = _read_check_meta("700")

        self.assertEqual(meta.get("severity"), "high")
        self.assertEqual(meta.get("cwe"), "CWE-502")


class RunnerIntegrationTests(unittest.TestCase):
    _FIXTURE = ROOT / "checks" / "community" / "proposed" / "700-cve-2026-9999-strict.sh"
    _created_fixture: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        cls._created_fixture = not cls._FIXTURE.is_file()
        if cls._created_fixture:
            cls._FIXTURE.parent.mkdir(parents=True, exist_ok=True)
            cls._FIXTURE.write_text(
                "#!/bin/bash\n"
                ": <<'PRESTON_META'\n"
                "schema_version: 1\n"
                "id: P-700\n"
                "name: CVE-2026-9999 strict detection\n"
                "category: code-scan\n"
                "severity: high\n"
                "languages: any\n"
                "min_tier: free\n"
                "provenance: auto\n"
                "version: 0.1.0\n"
                "PRESTON_META\n"
                'hits=$(grep -rn "CVE-2026-9999" "${SOURCE_DIR:-.}" 2>/dev/null || true)\n'
                'if [[ -n "$hits" ]]; then\n'
                '    record "FAIL" "P-700" "found CVE-2026-9999 reference"\n'
                'else\n'
                '    record "PASS" "P-700" "no CVE-2026-9999 reference"\n'
                'fi\n'
            )

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._created_fixture and cls._FIXTURE.is_file():
            cls._FIXTURE.unlink()

    def test_provenance_auto_routes_to_subshell(self) -> None:
        """Smoke test: a check with provenance:auto runs through the
        subshell-isolated path. Verifies preston-check.sh's run_check()
        function picks up the metadata correctly."""
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
