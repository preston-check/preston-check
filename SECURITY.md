# Security Policy

## Reporting a vulnerability

Preston-Check is itself a security tool. Vulnerabilities in it — false
negatives that miss real bugs, false positives that mislead, code-execution
issues in check scripts, supply-chain holes in our build pipeline — are
priority issues for us.

**If you think you've found a security issue, do not open a public GitHub
issue.** Instead, report it privately:

* Email: `security@preston-check.com` (preferred)
* GitHub Security Advisories: <https://github.com/preston-check/preston-check/security/advisories/new>

We will acknowledge receipt within two business days and aim to issue a fix
or mitigation within 30 days for high-severity issues. If you'd like
attribution in the release notes, say so in your report.

## Supported versions

We support the latest minor release on the `master` branch. Older minor
versions receive security fixes for 90 days after the next minor ships, at
which point they're considered end-of-life.

| Version | Supported          |
|---------|--------------------|
| 1.7.x   | :white_check_mark: |
| 1.6.x   | :white_check_mark: (until 2026-08-03) |
| < 1.6   | :x:                |

## Scope

In scope:

* The runner (`preston-check.sh`) and any code under `lib/`, `tools/`,
  `lang/`, `modules/`, `workers/`, `scripts/`, and `templates/`.
* Catalog checks under `checks/core/`, `checks/community/accepted/`, and
  `checks/community/verified/`.
* The official GitHub Action (`action.yml`) and Docker image
  (`docker/Dockerfile`).
* The installer script (`install.sh`) and any release artifacts published
  on GitHub Releases.
* The telemetry collector (`workers/telemetry/`) when deployed to the
  official preston-check.com endpoint.

Out of scope:

* Drafts under `checks/community/proposed/` (these are auto-generated and
  explicitly require maintainer review before promotion).
* Third-party tools we integrate with (Slither, Mythril, Echidna, Snyk,
  Drata, Vanta, Secureframe). Report issues to those vendors directly.
* Customer self-hosted deployments — we'll help you triage but the
  responsibility for the deployment is yours.

## Hardening defaults

Preston-Check ships with security-conscious defaults:

* **Network access is opt-in.** The runner makes zero network calls
  unless you pass `--ai-augment`, `--ai-fix`, `--telemetry-opt-in`, or
  set the equivalent env var. `--airgap` is the off-switch and overrides
  every opt-in flag.
* **Secrets are never logged.** AI augmentation sends finding context
  (file:line:content + ~10 surrounding lines) but explicitly never
  transmits the entire file or codebase.
* **Telemetry payload is minimal and salted.** See [docs/telemetry.md](docs/telemetry.md).
* **Releases are checksummed.** Every published tarball ships with a
  `.sha256` sidecar that the installer verifies before extraction.
* **Community checks run last and isolated.** Promoted checks live under
  `checks/community/accepted/`; unreviewed drafts under `checks/community/proposed/`
  only run when you pass `--include-proposed`.

## Disclosure timeline (recent)

This project is too young to have a meaningful disclosure history yet.
We will list resolved advisories here as they're issued.
