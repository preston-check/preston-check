# Changelog

All notable changes to Preston-Check are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.7.6] — 2026-05-04 — Manuals + HTML/PDF renderer + landing button fix

### Added

- `docs/manuals/` — eleven manuals scoped to specific audiences:
  user-manual, administrator-manual, selling-sheet, landing-page,
  customer-portal, admin-portal, telemetry-endpoint, standalone-worker,
  d1-dataset, github-release, homebrew-tap.
- `tools/build-docs.sh` — pandoc + Chrome renderer that produces
  HTML + PDF for every Markdown file under `docs/`. Output lands in
  `docs/_rendered/` (committed) so consumers don't need pandoc locally.
- `docs/operator-runbook.md` — single-page operator reference with
  every URL, resource ID, deploy procedure, and emergency runbook.

### Fixed

- Public landing page "Get started" button text was invisible due to
  CSS specificity — `header.site nav a { color: var(--ink); }` (0,1,3)
  beat `.btn-primary { color: var(--paper); }` (0,1,0). Scoped the
  nav-link rule to `:not(.btn)`.

### Removed

- `web/customer/functions/api/v1/telemetry/` and `_routes.json` —
  attempted Pages Function alternative for telemetry. Cloudflare's
  method dispatch fought us in ways the standalone Worker doesn't.
  The Worker is simpler, faster, and verified end-to-end. Single
  endpoint going forward.

### Changed

- `lib/telemetry.sh` default endpoint pinned to the standalone Worker
  at `preston-check-telemetry.preston-check-edge.workers.dev` (the
  workers.dev subdomain was renamed from a personal one to be
  anonymity-clean). `PRESTON_TELEMETRY_ENDPOINT` env var still
  honored for self-hosted overrides.


## [1.7.3] — 2026-05-04 — Release pipeline validated end-to-end

### Fixed

- `release.yml` was silently failing on every prior tag. Two job-level
  `if: ${{ secrets.X != '' }}` expressions are not actually permitted by
  GitHub Actions (the `secrets` context is unavailable at job-level `if`),
  so the workflow file was rejected before any step ran. Restructured the
  docker and homebrew jobs so secret-gating is a step-level guard that
  exits cleanly when secrets are absent. v1.7.3 is the first GitHub
  Release in the project's history.
- `tar -czf preston-check-${VERSION}.tar.gz .` aborted with "file changed
  as we read it" because the archive was being written into the directory
  it was reading. Tarball now lands in `../` then moves into place.
- `[[ $check_num -gt 20 ]]` after extracting filename prefixes like "08"
  or "09" caused bash to throw "value too great for base" warnings (octal
  parsing). Strip leading zeros before integer comparison.
- `--framework` filter wasn't reflected in the report header, so
  test workflow's `grep -q "PCI-DSS" fw-scan.md` always failed. Added
  Framework / Category / Severity lines to the report header.

### Added

- `--version` / `-V` flag.
- Homebrew tap formula bumped to v1.7.3 with verified sha256.

## [1.7.2] — 2026-05-04 — Deployment readiness

### Added

- `install.sh` — POSIX-sh sha256-verifying installer at the repo root,
  matching the README's `https://get.preston-check.com/install.sh`
  promise. Installs the catalog under `$PREFIX/share/preston-check` and
  a thin shim at `$PREFIX/bin/preston-check`.
- `SECURITY.md` — vulnerability disclosure policy, supported-versions
  table, scope list, hardening defaults summary.
- `examples/{github-action,gitlab-ci,circleci-config}.yml` and
  `examples/pre-commit-hook.sh` — drop-in usage patterns covering the
  four most-requested CI surfaces.
- `release.yml` — `install.sh` is now uploaded as a release asset, and a
  new `homebrew` job auto-bumps the tap formula when a `HOMEBREW_TAP_TOKEN`
  secret is configured.
- README — CI / Release / License badges; refreshed check count
  (236 → 294); surfaces `--ai-augment` / `--ai-fix`; links to `examples/`.

## [1.7.1] — 2026-05-03 — AI wired, threat-intel cron, telemetry docs

### Added

- `.github/workflows/threat-intel-sync.yml` — runs
  `tools/sync-threat-intel.py` weekly (Mondays 09:00 UTC) and on manual
  dispatch. Pulls fintech-relevant CVEs from NIST NVD, drafts checks under
  `checks/community/proposed/`, opens a PR via
  `peter-evans/create-pull-request@v6`. Verified end-to-end: 339 CVEs in
  a 2-day window, 135 fintech-relevant, drafts emit cleanly.
- `tools/sync-threat-intel.py` — new `--state-file` flag so CI can
  persist the processed-CVE state in `.preston-check/threat-intel-state.json`
  inside the repo, instead of the runner's home directory.
- `lib/ai_autofix.sh` — given a finding, produces a unified-diff patch
  via the same LLM provider as `ai_analyze.sh` (Anthropic / OpenAI /
  local Ollama). Per-finding cache so reruns don't re-bill. Conservative
  diff validation (only emits if response parses as a real diff).
- `--ai-augment` and `--ai-fix` flags on the runner. `--ai-fix` implies
  `--ai-augment`. Each FAIL/WARN finding gets analysis + (optional) patch
  in the report addendum, capped at 5 findings per check to bound scan
  time. Both flags are no-ops under `--airgap`.
- `docs/telemetry.md` — full privacy story, three opt-in mechanisms
  (flag, env, config), verification recipe with
  `PRESTON_TELEMETRY_ENDPOINT` override, self-hosting pointer for
  Enterprise air-gapped deployments.

### Fixed

- `lib/ai_analyze.sh` shipped in v1.6.0 but was never invoked from
  `preston-check.sh` — the runner had it sourced for nothing. Now
  actually called per finding when `--ai-augment` is on.

## [1.7.0] — 2026-05-03 — Smart Contract Audit Module + digital_escrow lessons

### Added — Smart Contract Audit Module (`modules/smart-contract-audit/`)

A separate runner for deep contract audits (longer runtimes,
narrative-friendly output, optional Slither/Mythril/Echidna integration)
parallel to the main pre-deploy gate. 20 deep checks across two phases
plus three integration wrappers.

- **Phase 2 catalog (P-700..P-709)** — proxy storage collision,
  initializer protection, selfdestruct, delegatecall abuse, front-running,
  cross-contract reentrancy, ERC-20 approve race, ERC-721/1155 callback
  reentrancy, token-economics math, governance attack vectors.
- **Phase 2 catalog (P-710..P-719)** — derived from production findings
  on a real HTLC + atomic-swap stack the maintainer audited:
  P-710 cross-chain replay (HTLC IDs without chainid + address(this)),
  P-711 on-chain preimage storage (cross-chain front-run),
  P-712 refund/claim authorization missing,
  P-713 timelock bypass via `&&` instead of `||`,
  P-714 emergency pause missing on fund-holding contract,
  P-715 critical immutable address without rotation path,
  P-716 unbounded array iteration (gas DoS),
  P-717 abi.encodePacked collision risk,
  P-718 untrusted bytes storage without length cap,
  P-719 insecure randomness from block data.
- **Integration wrappers** — `integrations/{slither,mythril,echidna}.sh`,
  opt-in via `--slither`, `--mythril`, `--echidna`.

Verified end-to-end against the digital_escrow contracts: P-712 PASSes
on the fixed `HTLCEscrow.sol` (recognizes the SC-C1 sender check),
P-710 correctly flags Tron HTLC variants missing chainid binding,
P-714 catches MPCShardStorage / TronSwapEscrow lacking pause paths.

### Added — strategy

- `docs/strategy/moat-strategy.md` + PDF — five-moat framework, AI
  roadmap by tier, UX two-act pattern, priority sequencing.
- `docs/strategy/gold-standard-playbook.md` + PDF — five-stage maturity
  model, eight specific moves, realistic timeline.

### Fixed

- `audit.sh` was inadvertently sourcing `preston-check.sh --help`, which
  has an `exit 0` in the help handler — that was silently killing the
  audit before any check ran. Removed the dead source line.

## [1.3.0] — 2026-05-03 — Roadmap completion: 8 frameworks + Go/Rust polyglot + severity filter

### Added — eight framework suites and polyglot parity (56 new checks)

- **NYDFS Part 500 (23 NYCRR 500)** suite (P-410..P-415, 6 checks):
  cybersecurity program documentation, CISO designation, annual risk
  assessment, pentest + vuln management, encryption of nonpublic info,
  expanded MFA scope per 2023 amendments.
- **OWASP Mobile Top 10 (2024)** suite (P-420..P-427, 8 checks):
  M1 improper credential usage, M2 supply chain, M3 insecure auth,
  M4 input/output validation, M5 insecure communication, M6 privacy
  controls, M7 binary protections, M8 misconfiguration.
- **OWASP LLM Top 10 (2025)** suite (P-430..P-437, 8 checks):
  LLM01 prompt injection, LLM02 sensitive disclosure, LLM03 supply
  chain, LLM04 data poisoning, LLM05 output handling, LLM06 excessive
  agency, LLM07 system prompt leakage, LLM10 unbounded consumption.
- **MAS TRM (Singapore)** suite (P-440..P-444, 5 checks):
  technology risk governance, cyber hygiene notice, customer
  authentication, system security testing, incident management.
- **APRA CPS 234 (Australia)** suite (P-450..P-453, 4 checks):
  information security capability, policy framework, vulnerability
  and threat management, incident notification.
- **RBI Cyber Security Framework (India)** suite (P-460..P-463, 4 checks):
  cyber security policy, network and database security, application
  security lifecycle, vendor / third-party risk.
- **PSD2 SCA** suite (P-470..P-474, 5 checks): SCA triggers, inherence,
  possession, knowledge elements, and dynamic linking on payment
  authorization.
- **3DS2 / 3-D Secure 2** suite (P-480..P-483, 4 checks): integration
  presence, frictionless / challenge flow handling, TRA exemption
  validation, card-on-file CIT/MIT distinction.
- **Go polyglot parity** (P-490..P-495, 6 checks): ignored error
  returns, float64 for money, race conditions, constant-time
  comparison, context cancellation, SQL injection patterns.
- **Rust polyglot parity** (P-500..P-505, 6 checks): unwrap()/expect()
  in production, integer overflow without checked_*, unsafe blocks
  without SAFETY comments, weak crypto crates, unverified serde
  deserialization, insecure random for cryptographic purposes.

### Added — severity filter and fast-core mode

- `--severity VAL[,VAL...]` flag to filter checks by metadata severity
  (critical, high, medium, low, info; comma-separated for multiple).
- `--critical-only` alias for `--severity critical` — runs only the
  highest-severity checks across the full catalog (~8-10 checks total,
  ~12-15 second runtime). Intended as the absolute fast-core run for
  pre-commit hooks where every second matters.
- `--high-and-up` alias for `--severity critical,high` — CI-blocking
  severity tier (~73 checks across the catalog).

### Changed

- Catalog total grew from 180 to 236 checks across 14 reputable
  frameworks. `--framework` filter and `--category` / `--severity`
  filters work uniformly across the full catalog.
- `--light` mode (P-01..P-20) preserved as the standing fast-core
  performance baseline. ~4 second runtime against an empty source
  directory; ~30 second runtime against a real fintech repo.

### Backward compatibility

- All existing checks unchanged. New checks are additive; no behavior
  changes to any prior runs.

## [1.2.0] — 2026-05-03 — DORA suite, full metadata coverage, CI/tests, private artifact strip

### Added

- DORA framework suite (P-400..P-407) — 8 checks covering EU Digital
  Operational Resilience Act (Regulation 2022/2554) requirements: ICT
  risk management framework, incident classification and reporting,
  threat-led penetration testing, third-party register, concentration
  risk, resilience testing program, threat intelligence sharing, and
  critical function ICT continuity (RTO/RPO).
- `.github/workflows/test.yml` — runs `bash -n` syntax checks across
  all scripts, executes the test suite, and validates `--framework`
  filtering on every push and PR.
- `.github/workflows/lint-community.yml` — automatically runs
  `tools/lint-check.sh` on every community PR plus shellcheck on all
  community check files.
- `.github/workflows/release.yml` — tag-triggered release workflow
  that builds the release tarball with private artifacts excluded,
  creates a GitHub Release, and (when Docker Hub credentials are set)
  builds and pushes multi-arch Docker images.
- Test fixture corpus under `tests/fixtures/{good,bad}/` with sample
  clean and vulnerable code for Java and Solidity, plus 28 smoke tests
  in `tests/lib/` covering metadata parsing, trust tier derivation,
  tier-allows-check policy, license loader, and PEM block extraction.
- Extended `COMPLIANCE_MAPPING.md` with control-level citations for
  P-65..P-103 (39 finance-extended checks) and P-200..P-280 (9 recently
  added categories), bringing total mapping doc coverage from 64 to
  112 sections.

### Fixed

- Metadata parser bug where OWASP-API citations were emitted as
  `OWASP-API:2023:API8:2023` (year duplicated). Now correctly emits
  `OWASP-API:2023:API8`.
- Metadata parser bug where NIST-CSF citations (format `PR.DS-1`,
  `DE.AE-2`) were not extracted because the regex didn't match the
  two-letter dotted notation. Now correctly captured across all 64
  control-level mapped legacy checks.
- `tools/sync-metadata-from-compliance-doc.py` per-framework regex
  patterns refactored from a single union pattern to dedicated patterns
  per framework, producing accurate citations for SOC 2 (`CC6.1`,
  `P1.1`), NIST CSF (`PR.DS-1`), OWASP API (`API8` without year
  duplication), and others.
- Added `--force-legacy` flag to the backfill script that strips and
  regenerates `PRESTON_META` blocks for legacy IDs (P-001..P-280),
  leaving the crypto suite (P-301..P-360) untouched.

### Changed

- All 112 legacy checks now have control-level framework citations
  (was: 64 mapped + 48 generic in v1.1.1). Re-running
  `tools/sync-metadata-from-compliance-doc.py --force-legacy` after
  any future COMPLIANCE_MAPPING.md update will roll changes forward.
- `.gitignore` now explicitly excludes `configs/bloxcross.yml`,
  `configs/operations.yml`, `configs/robbie.yml`, `blox-logo*.png`,
  `blox-logo*.svg`, `cycles/`, and `*.docx`. Files removed from git
  tracking but preserved on the local filesystem.

### Backward compatibility

- All existing checks continue to function. PRESTON_META blocks are
  bash heredoc-to-no-op constructs that introduce no behavioral change.

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
