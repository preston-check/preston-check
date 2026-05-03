# All Frameworks Reference

Preston-Check ships 236 checks mapped across 27 reputable frameworks. This
document is the canonical index — what's covered, by which checks, and how
to run a framework-scoped audit. Authoritative source URLs and the
maintenance procedure are in `docs/crypto-sources.md` and
`COMPLIANCE_MAPPING.md`.

Every check declares its framework citations in the `frameworks` field of
its `PRESTON_META` metadata block. The runner's `--framework` flag does a
case-insensitive substring match against that field, so the same flag
works regardless of which version of a framework the check pinned to.

## Card payments and 3-D Secure

**PCI-DSS v4.0** (PCI Security Standards Council). Filter:
`--framework "PCI-DSS"`. Coverage: P-01, P-13, P-14, P-15, P-17, P-18,
P-21, P-22, P-23, P-24, P-25, P-29, P-30, P-35, P-37, P-58, P-62, P-77,
P-83, P-84, P-101, P-102, P-103, P-200, P-220, P-230, P-240, P-260, P-270,
P-280, P-311, P-313, P-318, P-319, P-344, P-414. Roughly 80 of the 236
checks touch PCI-DSS v4.0 controls.

**PCI 3DS Core Security Standard** (3DS environment). Filter:
`--framework "PCI-3DS"`. Coverage: P-480, P-481, P-482, P-483.

**EMVCo 3DS 2.x**. Filter: `--framework "EMVCo-3DS"`. Coverage:
P-480 (integration presence), P-481 (frictionless and challenge flows),
P-482 (TRA and exemption validation), P-483 (card-on-file CIT/MIT).

## EU finance

**MiCA (Markets in Crypto-Assets Regulation 2023/1114)**. Filter:
`--framework MiCA`. Full applicability December 30, 2024 with member-state
transition until July 2026. Coverage: P-316 (hot wallet caps), P-320
(multi-sig discipline), P-322 (withdrawal whitelist), P-328 (Travel Rule
inheritance), P-358 (CCSS evidence as MiCA custody-audit input).

**EU Transfer of Funds Regulation (2023/1113)**. Filter:
`--framework "EU-TFR"`. Coverage: P-328 (Travel Rule on outbound
transfers).

**PSD2 (Payment Services Directive 2, Directive 2015/2366)**. Filter:
`--framework PSD2`. Coverage: P-330 (high-value step-up auth),
P-470..P-474 (the dedicated PSD2 SCA suite covering triggers, inherence,
possession, knowledge, and dynamic linking).

**PSD2 RTS (Commission Delegated Regulation 2018/389)**. Filter:
`--framework "PSD2-RTS"`. Coverage: P-470..P-474, P-481, P-482, P-483.

**DORA (Digital Operational Resilience Act 2022/2554)**. Filter:
`--framework DORA`. In force since January 2025. Coverage: P-400
(ICT risk framework), P-401 (incident reporting timelines), P-402
(threat-led pentest), P-403 (third-party register), P-404 (concentration
risk), P-405 (resilience testing program), P-406 (threat intelligence
sharing), P-407 (RTO/RPO for critical functions).

## US finance

**NYDFS Part 500 (23 NYCRR 500)**. Filter: `--framework "NYDFS"` or
`--framework "23NYCRR500"`. New York State's cybersecurity regulation
for licensed financial institutions, with material 2023 amendments.
Coverage: P-410 (cybersecurity program), P-411 (CISO designation),
P-412 (annual risk assessment), P-413 (pentest + vuln management),
P-414 (encryption of nonpublic info), P-415 (expanded MFA scope).

**FinCEN 31 CFR Chapter X**. Filter: `--framework FinCEN`. Coverage:
P-323 (pre-send risk scoring), P-328 (Travel Rule), P-336 (tainted-
funds tracing), P-79 (regulatory reporting readiness).

**OFAC SDN list**. Filter: `--framework OFAC`. Coverage: P-72
(sanctions screening), P-323 (pre-send risk scoring), P-324 (live SDN
freshness), P-327 (mixer detection — OFAC has sanctioned multiple
mixers), P-328 (Travel Rule), P-336 (tainted-funds tracing).

## Asia-Pacific finance

**MAS TRM (Singapore Monetary Authority Technology Risk Management)**.
Filter: `--framework "MAS-TRM"`. Coverage: P-440 (technology risk
governance), P-441 (cyber hygiene notice), P-442 (customer auth),
P-443 (system testing), P-444 (incident management).

**APRA CPS 234 (Australian Prudential Regulation Authority Prudential
Standard 234)**. Filter: `--framework "APRA-CPS234"`. Coverage: P-450
(infosec capability), P-451 (policy framework), P-452 (vuln + threat
management), P-453 (incident notification, 72-hour APRA notification).

**RBI Cyber Security Framework (Reserve Bank of India)**. Filter:
`--framework "RBI-CSF"`. Coverage: P-460 (cyber security policy),
P-461 (network and database security), P-462 (application security
lifecycle), P-463 (third-party / vendor risk).

## AML and sanctions

**FATF Recommendations 2023** (Financial Action Task Force). Filter:
`--framework FATF`. Coverage: P-322 (withdrawal whitelist), P-323
(pre-send risk scoring), P-324 (OFAC live screening), P-327 (mixer
detection), P-328 (Travel Rule, Recommendation 16), P-335 (counterparty
reputation, Recommendation 10), P-336 (tainted-funds source trace).

## General security

**SOC 2 Trust Service Criteria (AICPA, 2017)**. Filter: `--framework
SOC2`. Coverage: extensive — touches CC, A, P, C trust criteria across
P-01 through P-95, P-317 (key ceremony), P-450..P-453 (CPS 234 also
maps to SOC 2 categories).

**ISO/IEC 27001:2022**. Filter: `--framework "ISO-27001"`. Coverage:
extensive — Annex A controls mapped through P-01..P-95 plus crypto and
DORA suites.

**ISO 22301:2019** (Business Continuity Management). Filter:
`--framework "ISO-22301"`. Coverage: P-407 (DORA RTO/RPO), P-37
(backup and DR).

## OWASP family

**OWASP API Security Top 10 (2023)**. Filter:
`--framework "OWASP-API"`. Coverage: P-31, P-32, P-33, P-34, P-241
plus broader auth/rate-limit checks across P-01..P-20.

**OWASP Top 10 (2021)**. Filter: `--framework "OWASP-Top-10"`.
Coverage: P-08, P-13, P-14, P-15, P-16, P-17, P-18, plus polyglot
P-490, P-491, P-495, P-500, P-501, P-504.

**OWASP Mobile Application Security (MAS / MASVS 2.0, 2024)**. Filter:
`--framework "OWASP-MAS"` or `--framework "OWASP-MASVS"`. Coverage:
P-420..P-427 (the dedicated mobile suite), plus P-342, P-344, P-355.

**OWASP LLM Top 10 (2025)**. Filter:
`--framework "OWASP-LLM-Top-10"`. Coverage: P-430..P-437 (the dedicated
LLM suite covering LLM01-07 and LLM10).

**OWASP Smart Contract Top 10 (2025)**. Filter:
`--framework "OWASP-SC-Top-10"`. Coverage: P-301..P-310, P-348, P-349,
P-350, P-351, P-352, P-353, P-356, P-357.

## NIST family

**NIST Cybersecurity Framework 2.0**. Filter: `--framework "NIST-CSF"`.
Coverage: extensive across all suites — Govern, Identify, Protect,
Detect, Respond, Recover functions touched by approximately 100 checks.

**NIST FIPS 203 / 204 / 205 (Post-Quantum Cryptography)**. Filter:
`--framework FIPS` or `--framework "NIST-FIPS"`. Coverage: P-360 (PQC
readiness assessment).

**NIST SSDF 1.1 (Secure Software Development Framework)**. Filter:
`--framework "NIST-SSDF"`. Coverage: P-301 (smart contract reentrancy),
P-502 (Rust unsafe blocks).

## Crypto custody

**CCSS v9.0 (CryptoCurrency Security Standard, December 2024, by C4)**.
Filter: `--framework CCSS`. Three certification levels (1, 2, 3).
Coverage: P-311..P-320 (the key custody suite), P-344, P-345, P-354,
P-358 (CCSS evidence verification).

## Industry benchmarks

**CIS Controls v8 (Center for Internet Security)**. Filter:
`--framework "CIS-v8"`. Coverage: extensive across asset inventory,
secure configuration, audit logs, training, supplier management.

## Compliance run-recipes

For an EU-fintech multi-framework audit prep:

```bash
preston-check --framework MiCA  --report mica-audit.md  --config configs/myapp.yml
preston-check --framework DORA  --report dora-audit.md  --config configs/myapp.yml
preston-check --framework PSD2  --report psd2-audit.md  --config configs/myapp.yml
preston-check --framework FATF  --report fatf-audit.md  --config configs/myapp.yml
```

For a US fintech with NY exposure:

```bash
preston-check --framework NYDFS    --report nydfs.md
preston-check --framework "PCI-DSS" --report pci.md
preston-check --framework FinCEN   --report fincen.md
preston-check --framework OFAC     --report ofac.md
```

For a crypto exchange (any jurisdiction):

```bash
preston-check --framework CCSS  --report ccss-l2.md
preston-check --framework FATF  --report travel-rule.md
preston-check --framework "OWASP-SC-Top-10:2025" --report sc-audit.md
```

For an APAC fintech:

```bash
preston-check --framework "MAS-TRM"     --report mas.md
preston-check --framework "APRA-CPS234" --report apra.md
preston-check --framework "RBI-CSF"     --report rbi.md
```

For an LLM-driven fintech (chatbots, document processing, fraud detection):

```bash
preston-check --framework "OWASP-LLM-Top-10" --report llm-audit.md
```

## How filtering combines

The `--framework`, `--category`, `--severity`, `--code-only` /
`--docs-only` / `--infra-only` / `--live-only`, `--critical-only`,
`--high-and-up`, `--light`, and `--include-proposed` flags all stack.
A scan is the intersection of every active filter:

```bash
# DORA-scoped, evidence-only audit (skip code analysis)
preston-check --framework DORA --docs-only --report dora-evidence.md

# OWASP LLM Top 10, code-scan only, critical+high severity
preston-check --framework "OWASP-LLM-Top-10" --code-only --high-and-up

# NYDFS pentest evidence verification only
preston-check --framework NYDFS --docs-only --report nydfs-evidence.md

# Fast-core CI gate: critical-only across all frameworks
preston-check --critical-only --ci
```

This composability is the practical value: one tool, one configuration
file, scoped reports for any combination of regulators and risk areas.
