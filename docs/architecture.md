# Architecture

Preston-Check is a bash-based pre-deployment security scanner with an
open-core commercial model. This document describes the runtime architecture,
the open-source / commercial split, the component layout, and the data flow
during a scan.

## Component overview

The scanner has three layers:

The **engine** is `preston-check.sh` plus the `lib/` modules. It loads the
license, detects the source language, parses check metadata, filters by
tier, runs the selected checks, aggregates results, and renders the report.
All of this runs locally on the user's machine; no source code ever leaves
the host.

The **check catalog** is the collection of bash scripts under `checks/`.
Each script is sourced into the runner's shell, and exposes its findings
via the `record` function the runner exports. Checks live in one of six
locations: the legacy `checks/` root (treated as core for backward
compatibility), `checks/core/` (canonical maintainer-authored checks),
and the community trust-tier directories `checks/community/{verified,
accepted,proposed}/`.

The **commercial layer** is a separate proprietary product not included in
this repository. It receives generated reports from Pro/Enterprise customers
and produces the auditor-ready packaging: compliance evidence bundling,
branded PDF generation, multi-repo dashboards, customer portal, license
issuance backend, and SSO integration.

## Data flow during a scan

The runner starts by parsing CLI flags, then sources each `lib/*.sh` module
in order. License verification happens first because subsequent checks may
need to know the effective tier. License loading reads
`~/.preston-check/license` (overridable via `PRESTON_LICENSE`), extracts the
PEM-style payload and signature blocks, base64-decodes both, and verifies
the Ed25519 signature against the embedded public key at
`lib/license_pubkey.pem`. If any of these steps fail, the tool falls back
to the Free tier with a clear status note printed in the header.

Configuration loads next via the existing `load_config` function, which
extracts simple `key: value` pairs from the YAML-ish config file. Language
detection uses `lang/detect.sh` to find the dominant source language by
file count, then loads a language profile that exposes pattern variables
like `AUTH_ANNOTATION` and `BIG_DECIMAL_TYPE` for downstream checks.

OSS detection scans the source directory's LICENSE file to identify
recognized OSS licenses; if found, it bumps the effective tier from Free
to Pro for that scan. Branding configuration applies only at Enterprise
tier; at lower tiers, brand override fields are ignored with a stderr note.

The scan loop iterates over the six check directories. For each candidate
check file, the runner parses its metadata block and consults
`tier_allows_check` to decide whether to execute. Checks in directories
above the user's tier are silently skipped (or surfaced as `SKIP` entries
in `--verbose` mode). Each executed check sources into the runner's shell,
emits findings via `record`, and the runner accumulates pass/fail/warn/skip
counts.

Once all checks run, the runner prints a summary and (if `--report` was
passed) writes a markdown report. If `pandoc` and a PDF renderer are
available, it also generates a PDF. Finally, if telemetry is opted in and
airgap is off, the runner sends an anonymous score payload to the telemetry
endpoint as a best-effort background task.

## Open-source / commercial split

Everything in this repository is under Apache 2.0. The `lib/license.sh`
module is open-source — anyone can read it, audit it, fork it. The
*signing private key* and the *audit-package layer* are not in the
repository and constitute the commercial moat.

The audit-package layer is what Pro and Enterprise customers actually pay
for. Free customers get the markdown report. Pro customers get the report
plus compliance-evidence bundling, multi-repo aggregation, and branded
packaging. Enterprise customers get all of that plus white-label,
auditor-ready signed PDF deliverables, custom-check authoring support,
SSO, and a dedicated success contact.

Because the engine is open-source, customers can verify the privacy claim
themselves: there are no hidden network calls, the only optional outbound
request is the opt-in telemetry, and the license verification is fully
offline. This is intentionally counterintuitive — closing the engine would
weaken the trust story that makes the paid tier sellable.

## Trust tiers and the safety perimeter

Community contributions go through four trust tiers tied to filesystem
location. A check in `checks/community/proposed/` runs only with
`--include-proposed` and is treated as untrusted until reviewed. A check
in `checks/community/accepted/` has passed two maintainer reviews plus
the automated lint gates. A check in `checks/community/verified/` has
been promoted after at least six months of field validation and a
positive core-team vote. Checks in `checks/core/` are maintainer-authored.

The runner derives `trust_tier` from path, never from declared metadata.
This means a malicious contributor cannot bypass review by writing
`trust_tier: verified` in the metadata block — the runner ignores that
field entirely. The `tools/lint-check.sh` linter enforces additional
constraints at the directory level: community checks must use IDs in the
200-999 range, must declare `runtime_class: static-grep`, and must not
contain network calls, `eval`, `exec`, or file writes outside `/tmp`.
At runtime, the recommended hardening (not yet implemented) is to wrap
community-tier check execution in `bwrap` or `firejail` on Linux to
enforce the read-only filesystem invariant.

## License signing model

A single Ed25519 keypair is generated by the operator (you) once, via
`tools/setup-signing-key.sh`. The private key lives at
`~/.preston-check/keys/private.pem` and never leaves your machine. The
public half is committed to the repository at `lib/license_pubkey.pem`
so every customer instance can verify licenses offline.

To issue a license, you run `tools/issue-license.sh` with the customer
ID, tier, and expiry date. The tool builds a JSON payload, signs it with
the private key, and emits a PEM-style `.license` file the customer can
install at `~/.preston-check/license` or pass via the `PRESTON_LICENSE`
environment variable.

Rotating the signing key invalidates every existing license, so plan
rotations carefully: re-issue all licenses, then push the new public key,
then publish a new release. Back up the private key to an offline
secure location.

## Telemetry as the only outbound call

The tool makes exactly one optional network call: an anonymous score
ping to `preston-check.dev/api/v1/telemetry`, sent only when the user
opts in via `--telemetry-opt-in` or the config flag, and disabled
unconditionally by `--airgap`. The payload contains tool version, license
tier, primary language, aggregate counts, a SHA-256 hash of the git remote
origin URL (or source path), and a UTC timestamp. It never includes source
code, file paths, file names, customer details, or specific check IDs
that failed. The telemetry function in `lib/telemetry.sh` is intentionally
short and easy to audit because the privacy claim depends on you reading it.

The aggregate telemetry data feeds the annual State of Fintech Security
report, which is the planned tentpole content marketing artifact.
