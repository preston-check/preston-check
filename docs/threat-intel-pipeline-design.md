---
title: "Preston-Check — Auto-Evolving Threat-Intel Pipeline Design"
subtitle: "Architecture for a self-living, self-auditing security catalog with no human intervention"
audience: "operator + maintainers + IP counsel"
status: "canonical design reference"
related:
  - docs/threat-intel-pipeline-threat-model.md
  - docs/ip-moat-strategy.md
  - docs/architecture.md
  - docs/operator-runbook.md
---

# Auto-Evolving Threat-Intel Pipeline

This document is the canonical design reference for the auto-evolving
threat-intel pipeline that turns Preston-Check from a hand-curated
catalog into a self-living organism. The system reads from threat-intel
feeds continuously, synthesises detection patterns under a verification
wall, validates them against reproducible corpora, red-teams itself
adversarially, attests the resulting catalog changes publicly, gathers
field telemetry under a quorum gate, and continuously audits its own
gates so any decay is detectable before it can be exploited.

The design philosophy is wide-range intake combined with mechanical
verification walls strong enough to make human review unnecessary. The
test of correctness is not whether a maintainer would approve the
output but whether the gates that validate the output are themselves
continuously verified to be working as specified. That meta-
verification — auditing the auditor — is what makes the system
defensibly autonomous and what differentiates it from any human-
curated alternative.

The companion threat-model document at
`docs/threat-intel-pipeline-threat-model.md` enumerates the attack
surfaces and mitigations referenced throughout this design. The IP-
strategy document at `docs/ip-moat-strategy.md` explains why several
design decisions (reproducible corpora, public attestation, methodology
specification) are structured the way they are: those structures are
the operational manifestation of the IP moats.

## High-level architecture

The pipeline is seven coupled loops running at different cadences,
each with its own GitHub Actions workflow and its own state file. The
loops feed each other: ingestion produces candidates, synthesis turns
candidates into draft checks, validation scores drafts against
corpora, the adversarial loop hardens drafts that pass validation,
sandbox verification gates everything before it can land in the
catalog, field telemetry produces feedback streams that retune the
catalog, and drift detection plus the dual-use audit continuously
verify that every gate above is still functioning as specified.

```
                ┌──────────────────────────────────────────────┐
                │  Ingestion (KEV 15m, GHSA 1h, NVD/OSV 6h)   │
                └────────────────────┬─────────────────────────┘
                                     │  candidate-record JSON
                                     ▼
                ┌──────────────────────────────────────────────┐
                │  Synthesis (LLM, multi-variant, fixtures)   │
                └────────────────────┬─────────────────────────┘
                                     │  candidate-check JSON
                                     ▼
                ┌──────────────────────────────────────────────┐
                │  Sandbox (bash AST walker, capability gate) │ ◄─┐
                └────────────────────┬─────────────────────────┘   │
                                     │ pass                         │
                                     ▼                              │
                ┌──────────────────────────────────────────────┐   │
                │  Validation (TPR/FPR vs corpora, stability) │   │
                └────────────────────┬─────────────────────────┘   │
                                     │ pass                         │
                                     ▼                              │
                ┌──────────────────────────────────────────────┐   │
                │  Adversarial loop (model-diverse evasion)   │   │
                └────────────────────┬─────────────────────────┘   │ retry
                                     │ N rounds clean              │
                                     ▼                              │
                ┌──────────────────────────────────────────────┐   │
                │  Attestation + auto-merge (signed JSON, PR) │   │
                └────────────────────┬─────────────────────────┘   │
                                     │ merged to master             │
                                     ▼                              │
                ┌──────────────────────────────────────────────┐   │
                │  Shadow deploy (suppressed-output, 7 days)  │   │
                └────────────────────┬─────────────────────────┘   │
                                     │ quorum confirms                │
                                     ▼                              │
                ┌──────────────────────────────────────────────┐   │
                │  Surfaced (findings shown in user reports)  │   │
                └──────────────────────────────────────────────┘   │
                                                                   │
                ┌──────────────────────────────────────────────┐   │
                │  Field telemetry (Cloudflare Worker, D1)    │───┘ feedback
                │  + quorum-gated retire/tune/expand signals  │
                └──────────────────────────────────────────────┘
                ┌──────────────────────────────────────────────┐
                │  Drift detection (weekly TPR/FPR vs corpus) │
                └──────────────────────────────────────────────┘
                ┌──────────────────────────────────────────────┐
                │  Dual-use audit (red-team every gate daily) │
                └──────────────────────────────────────────────┘
```

## Verification wall philosophy

The verification wall is the mechanical safety perimeter that lets the
pipeline operate without human merge approval. Every layer of the wall
is independently verifiable, reproducible, and continuously audited.
No layer is permitted to depend on LLM compliance for safety; LLMs are
treated as untrusted code-generation tools whose output must pass
mechanical gates before it can affect anything.

Four properties define a wall layer. It must be **mechanical** —
specified as code, not as model behaviour. It must be **reproducible**
— the same input produces the same output every run. It must be
**measurable** — its effectiveness is a number that can be tracked
over time. And it must be **adversarially audited** — a separate
process continuously throws synthetic adversarial inputs at it and
records the results.

Layers ordered by where they sit in the pipeline:

The **bash AST walker** (`tools/sandbox-validate.py`) parses every
auto-generated check's bash body, walks the AST, and rejects anything
that uses operations outside an allowlist. Only `record`, `grep`,
`rg`, `find`, conditionals, loops, parameter expansion of named
variables, and reads from `$SOURCE_DIR` are permitted. Indirect
parameter expansion (`${!var}`), `printf -v`, `IFS` manipulation,
`eval`, command substitution into network calls, history expansion,
and the dangerous flags of permitted commands (`grep -P`, `rg --pre`,
`find -exec`) are rejected. Output is structured pass/fail with
specific reasons. The walker is itself audited daily by
`tools/sandbox-redteam.py`, which generates programmatically-varied
adversarial bash and records the catch rate.

The **subshell-isolated execution path** in the runner. Existing
maintainer-authored checks continue to be sourced (preserving
backward compatibility — `do_no_harm`). Auto-generated checks carry a
`provenance: auto` metadata flag in their `PRESTON_META` block, and
the runner detects this flag and runs those checks in a `bash -c`
subshell with reset `PATH`, unset `IFS`, dropped `BASH_ENV` and `ENV`,
and a fresh process scope. A malicious auto-generated check cannot
mutate the runner's state for subsequent checks, cannot exfiltrate
runner-scope variables, and cannot hijack the `record` function via
shell-level redefinition.

The **reproducible-corpus validation gate**. Every candidate check is
tested against a positive corpus (vulnerable code samples) and a
negative corpus (clean OSS samples in matching language/framework).
The corpora are built from public dataset manifests in
`corpus/manifests/` and produce deterministic SHA256 hashes. The
manifests pin specific commits or specific dataset versions, never
floating refs. A candidate must achieve TPR ≥ 0.85 on the positive
corpus and FPR ≤ 0.02 on the negative corpus, and must show
stability under light syntactic perturbations (whitespace, comment
insertion, identifier renames in irrelevant scopes). Failed
candidates re-enter the synthesis queue with their failure modes as
prompt feedback.

The **adversarial loop with enforced model diversity**. A second LLM,
running under different model weights from the synthesizer, is
shown the candidate pattern and the vulnerable code sample, and
asked to produce code that contains the vulnerability but evades the
pattern. Successful evasions are appended as new test cases to the
synthesis prompt and the loop re-runs. Promotion requires N=3
consecutive rounds with zero successful evasions. Model diversity is
enforced — synthesizer uses Anthropic, adversarial uses OpenAI or
Ollama; the providers rotate on a quarterly schedule to surface
evasion classes specific to either model's training distribution.

The **quorum-gated telemetry feedback**. The telemetry endpoint
`https://preston-check-telemetry.preston-check-edge.workers.dev` is
publicly POSTable by design (anonymity-preserving), so any feedback
signal it produces could in principle be poisoned by an attacker
flooding fake events. The quorum gate requires that any signal
acted on by the catalog (retire a check, tune a check, auto-revert
a recent merge) must come from at least N=10 distinct installation
fingerprints, distributed across at least M=14 days, with bounded
variance in geographic dispersion (UA-string anomaly detection
flags single-actor floods). Below quorum, signals are recorded but
not acted on.

The **continuous meta-verification of every gate above**. Every
gate's effectiveness is computed daily by `tools/dual-use-audit.py`
and logged to `docs/security-scorecard.md`, mirrored to a public
log endpoint. The AST walker's catch rate against a growing
corpus of synthetic adversarial bash. The validation gate's TPR/FPR
calibration against a held-out corpus the gate has not seen during
training. The adversarial loop's evasion-discovery rate against
intentionally-evasion-rich samples. The quorum gate's resistance
to simulated poisoning campaigns at varying scales. Any gate's
effectiveness drift below threshold pages the operator and pauses
auto-merge until investigated.

## Component-by-component design

### Ingestion

Four sources are wired in, each on its own cadence and each with
its own GitHub Actions workflow:

CISA Known Exploited Vulnerabilities (KEV). Polled every fifteen
minutes from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
Every entry is by definition actively exploited in the wild; this is
the highest-signal source and gets the most aggressive auto-merge
posture (lowest TPR threshold relaxation, since the cost of a missed
detection on actively-exploited bugs exceeds the cost of a
moderately-noisy false positive). Implemented in
`tools/ingest/kev.py`.

GitHub Security Advisories (GHSA). Polled hourly via
`gh api /advisories?per_page=100&sort=published`. Coverage is good
across most languages and frameworks Preston-Check targets.
Implemented in `tools/ingest/ghsa.py`. GHSA's lower review bar means
its candidates go through extra prompt-injection sanitisation in
synthesis.

NIST National Vulnerability Database (NVD). Polled every six hours
via the existing API in the current `sync-threat-intel.py`, with
the keyword filter retained but tightened. Implemented in
`tools/ingest/nvd.py`.

OSV.dev. Polled every six hours via
`https://api.osv.dev/v1/query`. Wider language and ecosystem
coverage than NVD or GHSA alone. Implemented in
`tools/ingest/osv.py`.

Each ingester writes normalised candidate records to
`.preston-check/queue/{source}-{timestamp}.json` for the synthesizer
to consume. Each ingester maintains its own state file at
`.preston-check/state/{source}.json` listing already-processed
identifiers. Each ingester applies a per-source budget cap (KEV
uncapped; GHSA $50/day in LLM costs; NVD $30/day; OSV $30/day) so
no single flooded source can drain the synthesis budget.

### Synthesis

`tools/synthesize-check.py` reads candidate records from the queue
and generates draft checks. For each candidate, the synthesizer
produces three variants — strict (low FPR, high FNR), permissive
(high FPR, low FNR), and middle. Each variant ships with two
synthetic test fixtures: a minimal positive sample the pattern is
expected to hit, and a minimal negative sample it is expected to
miss. The fixtures are validated as part of the candidate (the
positive must hit; the negative must miss) before any corpus
testing happens, eliminating obvious self-inconsistent candidates
early.

The synthesis prompt is a fixed template that passes the CVE
description as a tool-call argument under a structured schema, never
as inline system prompt content. Structural separation between
instructions and data is the primary mitigation against prompt
injection through CVE descriptions; the AST walker is the
mechanical safety net behind it.

The synthesizer uses Anthropic's API (Claude Opus 4.7 by default,
configurable via env var `PRESTON_SYNTH_MODEL`). API calls are
cached per (CVE-id, prompt-hash, model) to avoid re-spending LLM
budget on retries. Cache is in `.preston-check/synth-cache/`.

Each candidate is written to
`.preston-check/candidates/{P-NNNN}-{slug}.json` with the bash
body, fixtures, prompt-injection-sanitised metadata, the source
provenance, and a signature block (signed by the orchestrator's
ephemeral key) that anchors the candidate to its synthesis run.

### Sandbox validation

`tools/sandbox-validate.py` is the bash AST walker described in the
verification wall section. It uses a recursive descent over a
shell-grammar parse (using the `bashlex` library where available,
fallback to a subset parser for portability). Output is JSON with
`pass: bool` and `reasons: [str]`.

`tools/sandbox-redteam.py` is the daily auditor. It generates
synthetic adversarial bash variants programmatically (mutating
known-malicious patterns, combining allowed primitives in
unexpected sequences, attempting allowed-command-with-dangerous-
flags), runs each through the validator, and reports the catch
rate. A catch rate below 99.5% pages the operator. The harness's
test cases live in `tests/sandbox-redteam-fixtures/` and are
themselves versioned in the repo.

### Validation pipeline

`tools/validate-candidate.py` reads a candidate's bash body and
the corpora hashes from the candidate's manifest, runs the bash
body against every file in the positive corpus matching the
candidate's declared language/framework filter, computes TPR. Runs
against every file in the matching negative corpus, computes FPR.
Runs against perturbed copies of the positive corpus (whitespace
perturbation, comment insertion, identifier rename in irrelevant
scopes), computes stability score. Output is JSON with the four
metrics and per-file outcomes for forensics.

The corpora are checked out from versioned tarballs in
`corpus/snapshots/{date}.tar.gz.{hash}`. Build is
`tools/corpus-build.py` from manifests in `corpus/manifests/`.
Reproducibility is enforced by `tools/corpus-verify.py`, which
re-derives the corpus from the manifest and compares hash; any
hash mismatch fails the build.

The positive corpus is built from public exploit-DB samples,
HackerOne disclosed reports, and OSV-referenced PoC repositories,
each tagged in its manifest entry with vulnerability-class,
language, framework, and source URL.

The negative corpus is built from a curated subset of GHArchive's
permissive-licensed repos (Apache 2.0, MIT, BSD), filtered to
fintech-relevant frameworks (Spring Boot, FastAPI, Express, Rails,
Next.js, OpenZeppelin contracts), tagged similarly.

### Adversarial loop

`tools/adversarial-loop.py` orchestrates the model-diverse evasion
challenge. Inputs: the candidate's bash body and the validation-
run's per-file outcomes. For each positive-corpus file the candidate
correctly detects, the adversarial LLM is shown the file and the
pattern and prompted to produce a rewritten version that retains
the vulnerability but evades the pattern. Successful evasions are
re-tested by running the candidate against the rewritten file; if
the candidate misses, the rewritten file is appended to the
synthesis prompt for the next round.

The loop iterates up to N=3 rounds. Promotion requires the final
round to produce zero successful evasions. The adversarial LLM is
configured by env var `PRESTON_ADV_MODEL`, defaulting to
`gpt-4-turbo` (different provider from synthesizer). Quarterly the
operator rotates the adversarial model to a different provider/
version to prevent monoculture-blind-spots from accumulating.

The full adversarial transcript is hashed and recorded in the
candidate's attestation; the transcript itself is retained in
`attestations/{P-NNNN}/adversarial-transcript.json` and rotated
into `attestations/archive/` after one year.

### Attestation and auto-merge

`tools/attest.py` produces the cryptographically-signed JSON
attestation accompanying every catalog change. The attestation
schema:

```json
{
  "attestation_version": "1.0",
  "check_id": "P-NNNN",
  "source": {
    "type": "kev|ghsa|nvd|osv",
    "id": "CVE-2025-NNNN" or "GHSA-...",
    "fetched_at": "2026-05-08T14:00:00Z"
  },
  "synthesis": {
    "model": "claude-opus-4-7",
    "prompt_template_hash": "sha256:...",
    "variant": "strict|middle|permissive",
    "fixtures_pass": true,
    "ts": "2026-05-08T14:02:11Z"
  },
  "sandbox": {
    "validator_version": "0.1.0",
    "pass": true,
    "reasons": []
  },
  "validation": {
    "corpus_positive_hash": "sha256:...",
    "corpus_negative_hash": "sha256:...",
    "tpr": 0.92,
    "fpr": 0.008,
    "stability": 0.97
  },
  "adversarial": {
    "model": "gpt-4-turbo",
    "rounds": 3,
    "transcript_hash": "sha256:..."
  },
  "gate_effectiveness_at_merge": {
    "sandbox_redteam_catch_rate": 0.998,
    "validation_calibration_error": 0.012,
    "adversarial_evasion_rate": 0.034,
    "quorum_poisoning_resistance": 0.991
  },
  "signature": "ed25519:..."
}
```

The attestation is signed with the project's attestation Ed25519
key (separate from the SaaS license-signing key, narrower-scoped).
The public verifier `tools/attest-verify.py` checks signature
validity, schema compliance, and consistency between the
attestation and the corresponding check file.

`.github/workflows/threat-intel-orchestrate.yml` runs the
synthesis → sandbox → validation → adversarial → attestation
pipeline on a fifteen-minute cron, wakes per ingester completion,
and opens auto-merge PRs labelled `threat-intel/auto-merge`.
Branch protection requires the `sandbox`, `validation`, and
`adversarial` checks to be green before merge; the auto-merge
workflow also requires the attestation file to validate. PRs
that fail any gate are closed with the failure recorded; the
candidate re-enters the synthesis queue with the failure mode as
prompt feedback for retry.

The one human-in-the-loop carve-out is workflow-file changes.
Branch protection on `.github/workflows/**` requires signed
maintainer commits (using the operator's hardware key) and cannot
be bypassed by auto-merge. This prevents a single compromised PR
from rewriting the gates that all subsequent PRs must pass.

### Shadow deploy

When an auto-merge PR lands, the new check is initially in shadow
mode — its `PRESTON_META` block carries a `shadow_until: <date+7d>`
field. The runner's `should_run_check` logic detects this field
and, while the date is in the future, runs the check (so telemetry
records its hits) but suppresses the findings from the user-facing
report. The check's metadata declares its provenance as auto, so
it also runs in the subshell-isolated path.

Telemetry is aggregated nightly. A check that, over its shadow
window, demonstrates acceptable field behaviour (FPR signal under
threshold by quorum, no hit-rate anomalies) is auto-promoted by
removing the `shadow_until` field — another auto-merge PR. A
check that fails its shadow window is auto-reverted (the original
merge is reverted by an auto-PR) and the candidate re-enters
synthesis with telemetry-derived failure feedback.

### Field telemetry feedback loop

The existing telemetry Worker `preston-check-telemetry` is extended
to record per-check fire counts, per-check FP signals (an opt-in
runner flag `--report-fp <check-id>` lets users mark findings as
false positives), per-check error events (`record SKIP "error: ..."`).
All data is anonymised at submission time; per-installation
fingerprints are derived from a stable hash of the installation's
licence ID and an ephemeral salt.

`tools/telemetry-aggregate.py` runs nightly. It reads aggregated
counts from telemetry D1, applies the quorum gate, and produces
three feedback streams:

Retirement candidates: checks with zero hits across N=90 days at
high scan volume across at least 100 distinct installations get
flagged for retirement. The retirement is gated on a second pass
seven days later confirming the same signal — slow on purpose, to
prevent transient telemetry gaps from triggering retirements.

Tuning candidates: checks whose FP-signal rate per fire exceeds
threshold (configurable, defaulting to 0.15) across at least N=10
distinct installations over M=14 days. Tuning candidates re-enter
the synthesis pipeline with their FP cases as negative-corpus
augmentation for the next synthesis pass.

Coverage gaps: language/framework combinations represented in
opt-in scan metadata where no current check has fired in the past
90 days. These flow into a synthesis-priority queue so the
ingestion-keyword filtering can be biased toward CVEs in those
ecosystems.

Auto-revert: any check that, within 48 hours of merge, produces
an aggregate spike in `record SKIP "error: ..."` events from at
least N=10 distinct installations triggers an auto-revert PR. The
revert is automatic; the failed check returns to synthesis with
the error spike as feedback.

### Drift and decay

`.github/workflows/drift-detection.yml` runs weekly on a Sunday
03:00 UTC schedule. It checks the entire current catalog against
the latest positive and negative corpora, computes TPR/FPR per
check, and compares to the per-check baseline recorded at last
merge or last drift-pass. Checks whose TPR has dropped by more
than 10% (an upstream library renamed an API and the regex no
longer matches) are flagged for re-synthesis. Checks whose FPR
has risen by more than 0.02 are flagged for tuning.

The drift workflow auto-PRs the re-synthesis attempts. It does
not silently retire — retirement requires telemetry confirmation
through the field-feedback loop, not just corpus drift, because
corpus drift can reflect benign ecosystem evolution rather than
real check obsolescence.

### Dual-use audit

`tools/dual-use-audit.py` is the most distinctive component of
the design and the operational manifestation of the "self-auditing
beyond human scale" property. It runs four synthetic adversarial
campaigns daily:

Prompt-injection-laced CVE descriptions. Constructs CVE-record
JSON whose description text contains adversarial instructions
(known prompt-injection patterns, control-character Unicode tricks,
markdown-confusion patterns) and submits them to the synthesizer.
Records whether the synthesized candidates contain anything
outside the expected schema, fail the AST walker, or pass through
to the catalog. Expected: zero pass-throughs.

Sandbox-evasive bash. Generates programmatically-mutated bash that
attempts to reach restricted operations through allowed primitives
(parameter-expansion abuses, IFS tricks, allowed-command-with-
dangerous-flag combinations). Records the AST walker's catch rate.

Telemetry poisoning at varying scales. Submits synthetic telemetry
events designed to trigger unjustified retirement or tuning
signals. Records whether the quorum gate held. Tested at 5%, 25%,
and 50% poison ratios across a synthetic legitimate-traffic
baseline.

Corpus-poisoning-attempted PoCs. Constructs synthetic CVE
references pointing to crafted PoC repositories whose code is
designed to make a synthesized pattern look high-quality but
pattern-match commonly-used clean code. Records whether the
validation pipeline accepted the resulting candidate.

Each campaign produces a numerical effectiveness score (catch rate,
hold rate, refuse rate). Scores are written to
`docs/security-scorecard.md` daily and mirrored to a public log
endpoint. Dropping below configured thresholds pages the operator
via the existing alerting channel and pauses auto-merge until
investigated.

This is the layer the "no human could compete with" claim rests
on. A human maintainer cannot continuously red-team their own
verification gates at this scale; mechanical adversarial campaigns
running daily, against every gate, with public scorecards, are the
only known way to defensibly claim that gates without human
oversight are functioning as specified.

## State, storage, and reproducibility

Every component's persistent state is in one of four locations
chosen for explicit recoverability:

`.preston-check/` (gitignored, regenerable): per-source ingester
state, candidate queue, synthesis cache, validation outputs.
Regenerable from upstream sources and the LLM cache; loss is
recoverable in a few hours of re-running.

`corpus/` (committed): manifests pinning specific dataset versions,
verified-reproducible build script, and snapshot tarballs (gitignored
but pinned by hash in the manifest). Snapshots are regenerable
deterministically from manifests.

`attestations/` (committed): every signed attestation for every
catalog change since pipeline activation. Append-only by policy.
Older attestations migrated to `attestations/archive/` after one
year for repo size management; the public log endpoint retains
them indefinitely.

`docs/security-scorecard.md` (committed): daily-updated dual-use-
audit scorecard. The scorecard's append history is itself part of
the public record.

GitHub Actions workflows are pinned to specific action versions
(no floating refs) and use the project's `CLOUDFLARE_API_TOKEN`
only for telemetry-aggregate jobs that read from D1. The
synthesis, sandbox, validation, and adversarial workflows use
only the default `GITHUB_TOKEN` plus the LLM API keys (stored as
repo secrets `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`). Telemetry
write paths remain in the existing telemetry Worker; nothing in
this pipeline can write to telemetry.

## Performance and budget envelopes

The full pipeline is designed to operate within these envelopes:

KEV polling: 96 invocations per day × 1KB API call = trivial.

GHSA polling: 24 invocations per day × ~50KB API call = 1.2MB/day.

NVD/OSV polling: 8 invocations each per day × ~200KB = 3.2MB/day.

Synthesis LLM cost: estimated 10-30 candidates per day across all
sources × $0.50 per candidate (cached aggressively) = $5–15/day,
$150–450/month. Per-source budget caps prevent runaway cost.

Validation: 30 candidates × ~5min compute on GitHub Actions
ubuntu-latest runner = 2.5 GHA-hours/day, well within free tier.

Adversarial loop: 30 candidates × 3 rounds × $0.50 LLM = $45/day
worst case, $1350/month worst case. Realistic average lower with
caching, since most rounds reuse prior turns.

Drift detection: weekly full-catalog rerun against current
corpora = ~2 GHA-hours per week.

Dual-use audit: daily campaigns = ~30 GHA-min/day, ~15 GHA-
hours/month.

Total monthly LLM budget: $200–$2000 depending on threat-intel
volume and adversarial-round counts. Budget alarms fire at $500,
$1000, $2000.

## Migration from current state

The existing `tools/sync-threat-intel.py` and
`.github/workflows/threat-intel-sync.yml` are subsumed by this
design. Migration is staged:

Stage one (ships with this design doc): documentation only, no
runtime changes.

Stage two (sandbox + corpus + attestation): adds the verification
wall components without activating any auto-merge. Existing
weekly sync continues unchanged.

Stage three (multi-source ingestion + synthesis): replaces
`sync-threat-intel.py` with `tools/ingest/*.py` and
`tools/synthesize-check.py`. New workflows added; old workflow
deleted in same commit.

Stage four (validation + adversarial + auto-merge): activates the
full pipeline. Auto-merge initially gated on a kill-switch repo
secret `PRESTON_AUTOMERGE_ENABLED`; flipped to true after one
week of dry-run observation.

Stage five (telemetry feedback + shadow deploy + drift): wires up
the feedback loops.

Stage six (dual-use audit + scorecard publishing): activates the
meta-verification layer.

Each stage is a self-consistent commit; no stage leaves the
repository in a broken state.

## Cross-references

The threat model at `docs/threat-intel-pipeline-threat-model.md`
enumerates the attack surfaces this design defends against and the
specific mitigations applied at each layer.

The IP strategy at `docs/ip-moat-strategy.md` explains why several
design decisions are structured the way they are — particularly
the reproducible-corpus design, the public attestation schema, the
methodology specification angle, and the patentable inventions
embedded in the adversarial loop and quorum-gated telemetry.

The operator runbook at `docs/operator-runbook.md` is updated in
the same commit that activates each stage to reflect the new
workflows, secrets, and emergency procedures.

The architecture overview at `docs/architecture.md` is updated to
include this pipeline as a peer of the existing scanner runtime
architecture.
