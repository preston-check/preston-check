# Changelog

All notable changes to Preston-Check are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-05-03 — Productization release

### Added

- Open-core productization: Apache 2.0 license, separate commercial
  audit-package layer.
- Three pricing tiers: Free (no license), Pro ($999/repo/yr or $4,999/yr
  unlimited), Enterprise ($29,999+/yr).
- OSS exemption: repositories with recognized OSS LICENSE files
  (MIT/Apache/BSD/GPL/MPL/ISC/Unlicense) automatically receive Pro features.
- `lib/license.sh` — Ed25519 signed license verification, fully offline,
  strict enforcement with 30-day pre-expiry warnings.
- `lib/check_metadata.sh` — YAML schema parser; trust tier derived from
  filesystem path so contributors cannot self-declare higher trust.
- `lib/telemetry.sh` — opt-in only anonymous score telemetry, off by default,
  airgap-safe.
- `lib/branding.sh` — Enterprise-only white-label support.
- `lib/oss_detection.sh` — automatic OSS license detection.
- New CLI flags: `--airgap`, `--telemetry-opt-in`, `--include-proposed`,
  `--ci-soft`.
- Community contribution architecture under `checks/community/{proposed,
  accepted,verified}/` with path-derived trust tiers.
- `templates/check.sh` — fully-documented authoring template with required
  and optional metadata fields.
- `tools/lint-check.sh` — community check linter that bans network calls,
  eval/exec, and writes outside `/tmp`; validates schema and ID range.
- `tools/setup-signing-key.sh` — one-time Ed25519 keypair generator.
- `tools/issue-license.sh` — Pro/Enterprise license issuance with PEM-style
  envelope output.
- Distribution scaffolding: GitHub Action (`action.yml`),
  Docker image (`docker/Dockerfile`), Homebrew formula
  (`homebrew/preston-check.rb`), and `curl | bash` installer
  (`scripts/install.sh`).
- Legal documents: `LICENSE` (Apache 2.0), `NOTICE`, `TRADEMARK.md`,
  `CONTRIBUTING.md`, `CLA.md`.
- Documentation: `docs/architecture.md`, `docs/language-coverage.md`,
  `docs/financial-coverage.md`, `docs/compliance-coverage.md`,
  `docs/license-administration.md`, `docs/getting-started.md`,
  `docs/distribution.md`.
- Sample community check `P-201 GraphQL Introspection in Production` in
  `checks/community/proposed/`.

### Changed

- README rewritten to reflect open-core product, install channels, tier
  table, privacy posture, trademark policy, and contribution model.
- Main runner sources `lib/*.sh` modules at startup, prints license/OSS/
  telemetry/airgap status banners, filters checks by tier and trust tier,
  honors `--airgap` to disable all network paths, and emits report
  metadata (tier, customer, brand) when those are set.
- Report header and footer use `BRAND_NAME` and `BRAND_FOOTER` for
  Enterprise white-label support.
- `deploy-to-project.sh` copies the new `lib/`, `lang/`, `templates/`,
  and `checks/community/` directories so embedded copies remain functional.
- `--list` flag now enumerates checks across all six directory tiers
  (legacy root, core, community/{verified,accepted,proposed}).

### Backward compatibility

- All 112 existing checks run unchanged. The metadata parser falls back to
  filename-derived defaults when no `PRESTON_META` block is present, so
  legacy checks default to `min_tier: free` and continue to execute under
  the Free tier.
- Existing report format is preserved; new fields (Tier, Customer, Brand)
  are additive and only appear when relevant.

### Security

- License signature verification uses Ed25519 via `openssl pkeyutl
  -rawin`, requiring OpenSSL 1.1.1+ or LibreSSL with Ed25519 support.
- Telemetry (when opted in) sends only aggregate counts, language,
  license tier, and a SHA-256 hash of the git remote origin URL — never
  source code, file paths, or check names.
- Community check linter forbids network calls (`curl`, `wget`, `nc`,
  `/dev/tcp`), `eval`, and `exec` of dynamic input.

### Known gaps (roadmap)

- Language coverage is heavily Java/TypeScript-weighted; Rust, Go, and
  pure-JavaScript Node.js coverage is sparse. See
  `docs/language-coverage.md` for the per-language audit and roadmap.
- Several financial-application categories lack dedicated checks
  (PSD2 SCA, DORA operational resilience, smart contract reentrancy).
  See `docs/financial-coverage.md`.
- Compliance frameworks gaps include DORA, NIS2, NYDFS Part 500,
  MAS TRM, FFIEC IT Handbook, OWASP Mobile Top 10, OWASP LLM Top 10.
  See `docs/compliance-coverage.md`.
