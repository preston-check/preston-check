# Changelog

All notable changes to Preston-Check are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-05-03 — Crypto / DeFi suite

### Added

- Sixty dedicated crypto-business security checks (P-301..P-360)
  organized into six thematic groups:
  - Smart contract security (P-301..P-310): reentrancy, integer
    overflow, tx.origin authorization, unbounded loops, DEX slippage,
    oracle manipulation, token approvals, bridge replay, stablecoin
    peg monitoring, governance time-locks.
  - Key custody and storage (P-311..P-320): private-key/mnemonic
    exposure, HSM, KMS, MPC/threshold sigs, cold-wallet air-gap, hot-
    wallet caps, key ceremony, seed handling, key rotation, multi-sig.
  - Outbound transaction safety (P-321..P-330): address validation,
    withdrawal whitelist, blockchain analytics risk scoring, OFAC live
    screening, scam-address screening, address poisoning, mixers,
    Travel Rule, new-address cooldown, step-up auth.
  - Inbound asset hygiene (P-331..P-335): dust attacks, scam tokens
    and honeypots, unverified contract quarantine, NFT phishing,
    counterparty reputation.
  - Source wallet integrity (P-336..P-340): tainted-funds tracing,
    compromise indicators, approval audits, drainer pattern detection,
    reorg confirmation depth.
  - Extended key storage and token semantics (P-341..P-350): hardware
    wallets, secure enclaves, BIP-44 derivation paths, backup
    encryption, Shamir's Secret Sharing, in-process memory hygiene,
    fee-on-transfer tokens, proxy upgrade safety, EIP-2612 Permit
    replay, ERC-4337 account abstraction.
  - OWASP / Bybit / PQC / CCSS closure (P-351..P-360): comprehensive
    access control, flash loan attack resistance, unchecked external
    call returns, cold-to-hot transfer verification (Bybit Feb 2025
    lesson), blind signing prevention, DeFi liquidation safety,
    stablecoin admin freeze handling, CCSS evidence, emergency pause
    patterns, post-quantum cryptography readiness assessment.
- `--framework <NAME>` CLI flag for compliance-scoped runs (e.g.,
  `preston-check --framework MiCA`, `--framework "CCSS:9.0:Level2"`,
  `--framework "OWASP-SC-Top-10:2025"`, `--framework FATF`,
  `--framework OFAC`, `--framework FIPS`). Filter is a case-insensitive
  substring match against each check's `frameworks` metadata.
- `lang/detect.sh` now recognizes `*.sol` Solidity files (counts and
  fallback detection of `foundry.toml`, `hardhat.config.*`,
  `truffle-config.js`).
- `docs/crypto-coverage.md` — full 60-check breakdown.
- `docs/crypto-frameworks.md` — framework-to-check mapping for
  compliance-scoped runs.
- `docs/crypto-sources.md` — authoritative source registry with URLs,
  current versions, and per-source affected-check lists. Used by
  maintainers to keep checks aligned as standards evolve.

### Tier and licensing

- All sixty crypto checks default to `min_tier: free`. Crypto businesses
  can validate controls without a license; Pro and Enterprise tiers
  add value through the audit-package layer.

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
