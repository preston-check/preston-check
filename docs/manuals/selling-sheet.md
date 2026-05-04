---
title: "Preston-Check"
subtitle: "Pre-deployment security audit for fintech, narrowed and curated"
audience: "prospective customers, partners, press"
date: "2026-05-04"
geometry: margin=0.75in
---

# Preston-Check

**294 hand-curated security checks across 33 reputable frameworks.
Open source. Your code never leaves your machine.**

Pre-deployment security tools have a quality problem: scanners that try
to cover every domain end up covering none of them well. Preston-Check
is fintech-narrow on purpose — the catalog is 294 checks built from
real production audits, not 50,000 generic patterns crawled from public
repos. Lower noise. Higher signal. Faster scans. Cleaner reports your
auditor will actually read.

## What it covers

| Domain | Frameworks |
|---|---|
| Card payments | PCI-DSS v4.0 · PCI 3DS · EMVCo 3DS 2.x |
| EU finance | MiCA (2024) · TFR · PSD2 · DORA (2025) |
| US finance | NYDFS Part 500 · FinCEN 31 CFR · OFAC SDN |
| APAC | MAS TRM · APRA CPS 234 · RBI CSF |
| AML / sanctions | FATF Recommendations 2023 (incl. Travel Rule) |
| General security | SOC 2 (TSC 2017) · ISO 27001:2022 · ISO 22301:2019 |
| OWASP families | API Top 10 · Top 10 · Mobile MAS · LLM · Smart Contract |
| US framework | NIST CSF 2.0 · FIPS 203/204/205 (post-quantum) · SSDF 1.1 |
| Crypto custody | CCSS v9.0 |
| Cyber benchmarks | CIS Controls v8 |

Each check cites the framework control it stems from and (where
applicable) the real-world incident that motivated it. Wormhole bridge.
Cetus integer overflow. Beanstalk Farms governance attack. The catalog
is the post-mortem turned into automated regression tests.

## What makes it different

**Curated, not crawled.** 294 checks where each has a name,
a story, and a citation. Not 50,000 patterns scraped from public
repos.

**AI auto-fix.** Pass `--ai-fix` and every finding comes with a
suggested unified-diff patch. Apply with `git apply`, ship the fix.

**Privacy-first.** Open-source scanner. Telemetry is opt-in.
`--airgap` blocks every outbound call. The privacy promise is
auditable in 30 lines of bash.

**One surface, every CI.** Same exit codes and the same Markdown
report whether you run it as a CLI, GitHub Action, GitLab CI job,
CircleCI step, Docker image, Homebrew install, or pre-commit hook.

**Compliance evidence bundles.** Filter by framework, generate a
PDF mapped to the control catalog, hand it to your auditor.

## How it works

```bash
brew install preston-check/preston-check/preston-check
preston-check --high-and-up --ci --report security-audit.md
```

A typical fintech codebase scan completes in 30 seconds to 3 minutes
depending on size and severity filter. The report is plain Markdown
plus a PDF version, with three-tier triage (FAIL must fix, WARN review,
PASS / SKIP for context). Drop into your CI; fail the build on any
critical finding.

## Pricing

| | Free | Pro | Enterprise |
|---|---|---|---|
| Price | $0, no signup | $999/repo/yr or $4,999/yr unlimited | $29,999+/yr |
| Catalog | All 294 checks | All 294 checks | All 294 checks + custom |
| AI augmentation | Bring your own API key | Bring your own API key | Bring your own API key |
| Markdown + local PDF reports | ✅ | ✅ | ✅ |
| Branded PDF reports | — | ✅ | ✅ |
| Multi-repo dashboard | — | ✅ | ✅ |
| Compliance evidence bundles | — | ✅ | ✅ |
| SSO (SAML / OIDC) | — | — | ✅ |
| White-label dashboards | — | — | ✅ |
| Custom check authoring | — | — | ✅ |
| SLA-backed support | — | — | ✅ |
| On-premise deployment | — | — | ✅ |

**OSS exemption** — repositories with a recognized open-source license
automatically get free Pro tier. Public security work makes the
community stronger; a fintech maintaining an open-source library
shouldn't pay to scan it.

## Why now

The fintech security landscape has gotten harder, not easier. MiCA
(EU 2024) and DORA (EU 2025) just landed. NYDFS Part 500 amendments
expanded MFA scope in 2023. Travel Rule enforcement is now active
across G20 jurisdictions. OWASP shipped a Smart Contract Top 10 in 2025.
The FATF Recommendations got a substantial update.

Most security tools haven't caught up. We have. Preston-Check ships a
weekly threat-intel auto-ingestion pipeline that drafts new checks
from CVE feeds and recent breaches, so the catalog grows faster than
humans alone can write it.

## Ready to start

```bash
curl -fsSL https://get.preston-check.com/install.sh | sh
preston-check
```

Free forever. No signup. No telemetry by default. Apache 2.0.

For enterprise: `sales@preston-check.com`
For technical: `https://github.com/preston-check/preston-check`
For media: `press@preston-check.com`

---

*Preston-Check — named after the attacker, calibrated against 1.3
million logged session and request traces from the original incident,
maintained as a public-good open-source project.*
