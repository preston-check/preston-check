# Preston-Check — Pre-Deployment Security Audit Tool

[![Tests](https://github.com/preston-check/preston-check/actions/workflows/test.yml/badge.svg)](https://github.com/preston-check/preston-check/actions/workflows/test.yml)
[![Release](https://github.com/preston-check/preston-check/actions/workflows/release.yml/badge.svg)](https://github.com/preston-check/preston-check/releases/latest)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Apache 2.0 open-source, community-grown, fintech-focused. **294 automated security checks** spanning **33 reputable frameworks** run locally against your source code (284 main catalog + 10 deep smart-contract audit). Your code never leaves your machine unless you opt in. AI-augmented finding analysis and patch suggestions are available via `--ai-augment` / `--ai-fix`.

Named after Preston Braswell, a real hacker who created multiple fake accounts, bypassed 2FA, ran 21,201 automated session polling calls, and probed for race conditions and information leakage on a production fintech platform. This tool codifies the lessons learned from that attack — and from the broader fintech security catalog — into automated checks you can run before every deployment.

## Frameworks Covered

| Category | Frameworks |
|---|---|
| Card payments | PCI-DSS v4.0, PCI 3DS, EMVCo 3DS 2.x |
| EU finance | MiCA (2024), TFR (2023), PSD2 + PSD2-RTS, DORA (2025) |
| US finance | NYDFS Part 500 (23 NYCRR), FinCEN 31 CFR, OFAC SDN |
| APAC | MAS TRM (Singapore), APRA CPS 234 (Australia), RBI CSF (India) |
| AML / sanctions | FATF Recommendations 2023 (incl. Travel Rule Rec.16) |
| General security | SOC 2 (TSC 2017), ISO 27001:2022, ISO 22301:2019 |
| OWASP families | API Top 10 2023, Top 10 2021, Mobile MAS 2024, LLM 2025, Smart Contract Top 10 2025 |
| US framework | NIST CSF 2.0, FIPS 203/204/205 (post-quantum), SSDF 1.1 |
| Crypto custody | CCSS v9.0 (CryptoCurrency Security Standard) |
| Cyber benchmarks | CIS Controls v8 |

## Install

```bash
# Homebrew (macOS / Linux)
brew tap preston-check/preston-check && brew install preston-check

# Docker
docker run --rm -v $(pwd):/src prestoncheck/scan:latest

# curl | bash
curl -fsSL https://get.preston-check.com/install.sh | sh

# GitHub Action (in your .github/workflows/)
- uses: preston-check/scan-action@v1
```

## Quick Start

```bash
# Scan the current directory (Free tier, no license needed)
preston-check

# Scan with a project config
preston-check --config configs/myapp.yml

# CI mode — exits 1 on any FAIL
preston-check --ci --report security-audit.md

# Light mode (P-01..P-20 only, ~4-30s)
preston-check --light

# Critical-only fast-core run (~12s, blocking issues only)
preston-check --critical-only

# CI-blocking severity (critical + high, ~73 checks)
preston-check --high-and-up --ci

# Run a single check
preston-check --check 07-blacklist-check

# Airgap mode (no network calls, ever)
preston-check --airgap

# Opt in to anonymous score telemetry (helps the community)
preston-check --telemetry-opt-in

# Run unreviewed community-contributed checks
preston-check --include-proposed

# AI-augment findings (requires ANTHROPIC_API_KEY or OPENAI_API_KEY)
preston-check --ai-augment

# AI-augment AND emit suggested patches per finding
preston-check --ai-fix
```

## Examples

Production-ready usage patterns live in [`examples/`](examples/):

* [`examples/github-action.yml`](examples/github-action.yml) — drop-in PR security gate
* [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) — GitLab CI integration
* [`examples/circleci-config.yml`](examples/circleci-config.yml) — CircleCI integration
* [`examples/pre-commit-hook.sh`](examples/pre-commit-hook.sh) — local pre-commit gate


## Filter by framework, category, or severity

```bash
# Compliance-scoped audit reports
preston-check --framework "PCI-DSS" --report pci-audit.md
preston-check --framework MiCA --report mica-audit.md
preston-check --framework DORA --report dora-audit.md
preston-check --framework "NYDFS" --report nydfs-audit.md
preston-check --framework "OWASP-LLM-Top-10" --report llm-audit.md

# Filter by what kind of check
preston-check --code-only       # pure source-code analysis
preston-check --docs-only       # policy / evidence documentation only
preston-check --infra-only      # infrastructure config only
preston-check --live-only       # SSH-based production log checks

# Filter by severity
preston-check --severity critical,high
preston-check --critical-only

# Combine: DORA-scoped, code-only run for CI
preston-check --framework DORA --code-only --ci
```

## Privacy by design

Preston-Check reads your source files and never sends them anywhere. It is open-source so you can verify this yourself. The only network call the tool can make is opt-in anonymous score telemetry that contributes to the annual State of Fintech Security report — and even that is disabled by `--airgap`. There is no required signup, no email gate, and no account for the Free tier.

## Tiers

| Tier | Price | What you get |
|---|---|---|
| Free | $0 | All scanning checks (P-01..P-103+), unlimited repos, no license required |
| Pro | $999/repo/yr or $4,999/yr unlimited | Compliance-evidence layer (P-83..P-95), multi-repo dashboard, branded reports, priority email support |
| Enterprise | $29,999+/yr | White-label reports, SSO, custom check authoring, signed audit packages, dedicated support |

OSS exemption: any repository with a recognized OSS LICENSE file (MIT, Apache, BSD, GPL, MPL, ISC) gets Pro features automatically and free. This is intentional — public security work makes the community stronger.

License enforcement is strict on Pro/Enterprise (expired licenses block paid features) with a 30-day pre-expiry warning printed in every report so renewals never sneak up on you.

## Trademark and forks

Preston-Check is licensed under Apache 2.0. The "Preston-Check" name and logo are trademarks — see TRADEMARK.md for what is permitted (using the badge in your README, mentioning the tool in articles, etc.) and what requires permission (naming a fork, registering domains, etc.). The audit-package layer (compliance-evidence bundling, branded report generation, multi-repo dashboard, customer portal, license issuance) is a separate commercial product distributed under proprietary terms.

## Contributing

Community contributions are welcome via the trust-tier system documented in CONTRIBUTING.md. Drop new checks into `checks/community/proposed/`, fill in the metadata block (see `templates/check.sh`), run `tools/lint-check.sh path/to/check.sh`, and open a PR. Maintainer review promotes proposed → accepted, and field validation eventually promotes accepted → verified. Author attribution is shown in every report.

## Crypto / DeFi suite (P-301..P-360)

Sixty dedicated checks covering smart contract security, key custody, outbound transaction safety, inbound asset hygiene, source-wallet integrity, and regulatory compliance. Aligned to OWASP Smart Contract Top 10 (2025), CryptoCurrency Security Standard v9.0, NIST CSF 2.0, FATF Travel Rule, MiCA, OFAC, NIST FIPS post-quantum standards, and CCSS Level 1-3 evidence requirements. See `docs/crypto-coverage.md` for the full breakdown.

Run by compliance framework:

```bash
preston-check --framework MiCA              # EU MiCA crypto-asset service provider audit
preston-check --framework "CCSS:9.0:Level2" # CCSS Level 2 self-assessment
preston-check --framework "OWASP-SC-Top-10:2025"
preston-check --framework FATF              # Travel Rule + sanctions
preston-check --framework OFAC
preston-check --framework FIPS              # NIST post-quantum readiness
```

Mapping is in `docs/crypto-frameworks.md`. Authoritative sources tracked in `docs/crypto-sources.md` so checks can be updated as frameworks evolve.

## Existing check catalog

## Directory Structure

```
~/DEV/preston-check/
  preston-check.sh          Main runner script
  config.yml                Default config (scans current directory)
  deploy-to-project.sh      Copy preston-check into another project
  README.md                 This file
  configs/                  Per-project configurations
    bloxcross.yml           Bloxcross main platform
    operations.yml          Operations Portal
  checks/                   Individual check scripts (20 categories)
    01-hardcoded-secrets.sh
    02-2fa-bypass.sh
    03-info-leakage.sh
    04-rate-limiting.sh
    05-idempotency.sh
    06-session-security.sh
    07-blacklist-check.sh
    08-input-validation.sh
    09-audit-trail.sh
    10-live-attack-indicators.sh
    11-tls-encryption.sh
    12-financial-guards.sh
    13-auth-enforcement.sh
    14-dependency-security.sh
    15-cors-csrf.sh
    16-error-handling.sh
    17-secure-random.sh
    18-data-privacy.sh
    19-api-versioning.sh
    20-deployment-safety.sh
```

## Per-Project Configuration

Each project gets a YAML file in `configs/`. Create one per project:

```yaml
# configs/myapp.yml

# Name shown in report header
app_name: my-payment-app

# Path to source code root (REQUIRED — where src/, pom.xml, package.json live)
source_dir: /home/user/projects/my-payment-app

# Remote server log directory (for P-10 live attack checks)
log_dir: /home/ec2-user

# SSH hostname for live checks (leave empty to skip P-10)
ssh_host: my-production-server

# API base URL (for future HTTP-based checks)
api_base_url: https://api.my-payment-app.com

# Redis host (for future session checks)
redis_host: localhost

# Database host (for future DB checks)
db_host: my-db.rds.amazonaws.com
```

The only required field is `source_dir`. Everything else is optional. If `ssh_host` is empty, the live attack indicator checks (P-10) are skipped.

### Existing Configs

| Config | Project | SSH Host |
|---|---|---|
| `configs/bloxcross.yml` | Bloxcross fintech platform | sandbox-cluster-001 |
| `configs/operations.yml` | Operations Portal (Express/React) | ops |

### Adding a New Project

```bash
cat > ~/DEV/preston-check/configs/new-project.yml << EOF
app_name: new-project
source_dir: /path/to/new-project
log_dir: /var/log/app
ssh_host: new-project-prod
api_base_url: https://api.new-project.com
redis_host: localhost
db_host:
EOF
```

## Security Checks (100 categories, 276 test points)

Organized by compliance framework. Each check maps to one or more of: PCI-DSS v4.0, SOC 2 Type II, ISO 27001:2022, OWASP API Top 10, NIST CSF 2.0, CIS Controls v8. See COMPLIANCE_MAPPING.md for the full mapping. With the compliance evidence directory (compliance-template/), all six frameworks reach 100% coverage.

### Code Scanning (P-01 to P-09) — runs against source_dir

| # | Category | What It Catches | Origin |
|---|---|---|---|
| P-01 | Hardcoded Secrets | API keys, passwords, AWS keys in source code | Preston found exposed JWT secret in git history |
| P-02 | 2FA Bypass | Code paths that skip or disable two-factor auth | Preston created accounts with 2FA=NONE |
| P-03 | Info Leakage | Exception messages, sensitive fields in API responses | Preston's session polling leaked Vouched keys + fee structure |
| P-04 | Rate Limiting | Endpoints without rate limiting | Preston made 21,201 calls at 1-2 second intervals |
| P-05 | Idempotency | Webhooks and financial ops without replay protection | Double-spend attacks via webhook replay |
| P-06 | Session Security | Missing IP binding, no TTL, no kill mechanism | Preston exploited sessions with no IP validation |
| P-07 | Blacklist | Registration/KYC paths that don't check the blacklist | Preston created new accounts after being blacklisted |
| P-08 | Input Validation | SQL injection, command injection patterns | Standard OWASP check |
| P-09 | Audit Trail | Missing DB triggers, no append-only enforcement | Financial data must be immutable |

### Live Monitoring (P-10) — runs via SSH against production logs

| # | Category | What It Catches |
|---|---|---|
| P-10 | Live Attack Indicators | Active brute force, rapid polling, blacklist events, 2FA failures on withdrawals |

### Platform Security (P-11 to P-20) — runs against source_dir

| # | Category | What It Catches | Why It Matters for Financial Systems |
|---|---|---|---|
| P-11 | TLS/Encryption | Plaintext HTTP, weak crypto (DES/RC4/MD5/ECB), SSL not configured | Credentials and financial data must be encrypted in transit |
| P-12 | Financial Guards | Missing balance checks, no locking, no negative amount validation | Prevents double-spend, overdraft, negative-amount exploits |
| P-13 | Auth Enforcement | Controllers without auth, missing JWT verification | Every endpoint handling money must require authentication |
| P-14 | Dependencies | Vulnerable libraries, SNAPSHOT deps in production | Known CVEs in dependencies are the #1 attack vector |
| P-15 | CORS/CSRF | Wildcard origins, missing CSRF tokens | Prevents cross-site request forgery on financial operations |
| P-16 | Error Handling | printStackTrace, empty catch blocks, stack trace leaks | Errors expose internal architecture to attackers |
| P-17 | Secure Random | java.util.Random instead of SecureRandom | Predictable tokens, codes, and IDs enable session prediction |
| P-18 | Data Privacy | Plaintext passwords, PII in logs, missing @JsonIgnore | Regulatory requirement (GDPR, PCI-DSS, SOC2) |
| P-19 | API Versioning | Unversioned APIs, active deprecated endpoints | Deprecated endpoints may lack newer security fixes |
| P-20 | Deployment Safety | Debug mode, test credentials, health endpoints, migrations | Production must never have dev-mode shortcuts |

## Result Levels

| Level | Meaning | Action Required |
|---|---|---|
| PASS | Check passed | None |
| FAIL | Critical security issue | Must fix before deployment |
| WARN | Potential issue, needs review | Review and decide if acceptable |
| SKIP | Check could not run (missing config or data) | Configure the relevant setting |

## Deploying to a New Project

Two options:

### Option A: Use the global instance (recommended)

Just create a config file and run:
```bash
# Create config
cat > ~/DEV/preston-check/configs/myapp.yml << EOF
app_name: myapp
source_dir: /path/to/myapp
ssh_host: myapp-prod
EOF

# Run
~/DEV/preston-check/preston-check.sh --config ~/DEV/preston-check/configs/myapp.yml
```

### Option B: Copy into the project (for CI/CD)

```bash
~/DEV/preston-check/deploy-to-project.sh /path/to/myapp myapp myapp-prod
```

This copies everything into `/path/to/myapp/tools/preston-check/`, generates a local config, and runs the first audit. The project can then commit the tool into its own repo for CI/CD.

## CI/CD Integration

### GitHub Actions
```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Preston Security Audit
      run: |
        chmod +x ./tools/preston-check/preston-check.sh ./tools/preston-check/checks/*.sh
        ./tools/preston-check/preston-check.sh --ci --report security-audit.md
    - name: Upload Report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: security-audit
        path: security-audit.md
```

### GitLab CI
```yaml
security_audit:
  stage: test
  script:
    - chmod +x ./tools/preston-check/preston-check.sh ./tools/preston-check/checks/*.sh
    - ./tools/preston-check/preston-check.sh --ci --report security-audit.md
  artifacts:
    paths: [security-audit.md]
    when: always
```

### Pre-push Git Hook
```bash
echo '~/DEV/preston-check/preston-check.sh --ci --config ~/DEV/preston-check/configs/myapp.yml' >> .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

## Adding Custom Checks

Create a new file in `checks/` following the naming convention:

```bash
#!/bin/bash
# P-21: My custom check
# Explain why this check matters and what attack it prevents.

echo "P-21: My Custom Check"

SRC="${SOURCE_DIR:-.}"

# Your detection logic here
result=$(grep -rn --include="*.java" "dangerous_pattern" "$SRC" 2>/dev/null | wc -l)

if [[ $result -eq 0 ]]; then
  record "PASS" "P-21 My check" "No issues found"
else
  record "FAIL" "P-21 My check" "$result issues found"
fi
```

The `record` function is provided by the main runner. It takes three arguments:
1. Status: `PASS`, `FAIL`, `WARN`, or `SKIP`
2. Check name (shown in the report)
3. Detail message

## Handing Off to a New Claude Session

Start a new Claude Code session and say:
```
Read ~/DEV/preston-check/README.md. Run a security audit on [project name]
using ~/DEV/preston-check/configs/[project].yml. Fix any FAIL results.
```

The session will have full context on all 20 check categories, how to run them, and how to interpret/fix results.

## Background

Preston Braswell's attack on a production fintech platform in February 2026 involved:

1. Creating 5+ fake accounts with synthetic names and disposable phone numbers
2. Setting 2FA to NONE on all accounts
3. Running 21,201 automated calls to a configuration endpoint at 1-2 second intervals
4. Exploiting session responses that leaked third-party API keys, fee structures, and internal permissions
5. Credential stuffing with non-existent emails, then registering with a stolen payment-API key
6. Attempting custodial withdrawals with wrong 2FA codes and balance probing

Every check in this tool is derived from a real attack pattern observed in the forensic logs. The catalog is the post-mortem turned into automated regression tests.

## Enhanced Checks (P-21 through P-56) — Enterprise Security Suite

### Compliance & Regulatory
| # | Check | What It Catches |
|---|---|---|
| P-21 | PCI-DSS Card Data | Raw PAN in source/logs, missing tokenization |
| P-22 | AML Transaction Monitoring | Missing CTR thresholds, no structuring detection, no SAR mechanism |
| P-23 | KYC Document Security | S3 encryption, presigned URL duration, file type validation |
| P-24 | Data Retention | Redis without TTL, no GDPR erasure mechanism |

### Infrastructure Security
| P-25 | AWS IAM Hygiene | Static AWS credentials, missing Secrets Manager |
| P-26 | Network Exposure | Redis without auth, management ports exposed |
| P-27 | TLS Certificate (Live) | Cert expiry, HSTS headers |
| P-28 | WAF & DDoS | Missing WAF integration, no geo-blocking/OFAC |

### API Security (OWASP Top 10)
| P-29 | Webhook Signatures | Per-handler signature verification for payment webhooks |
| P-30 | HMAC Integrity | Filter coverage, replay protection, algorithm strength |
| P-31 | BOLA Authorization | Resource IDs without ownership verification |
| P-32 | Mass Assignment | Raw entities as @Body, missing DTO pattern |
| P-33 | Resource Limits | Request body size, HTTP timeouts, pagination |
| P-34 | SSRF Prevention | User URLs in HTTP clients, metadata endpoint blocking |

### Data Protection
| P-35 | Database Encryption | SSL enforcement, SELECT * overfetching |
| P-36 | Key Management | Key files in repo, rotation mechanisms |
| P-37 | Backup & DR | Backup references, DR docs, migration rollbacks |

### Operational Security
| P-38 | Security Logging | Login/transaction/admin action logging completeness |
| P-39 | Alerting & Monitoring | Circuit breakers, alert integration |
| P-40 | Incident Response | Session revocation, IR documentation |

### Supply Chain
| P-41 | Dependency Pinning | Maven versions, npm lock files, Docker tags |
| P-42 | CI/CD Security | Credentials in scripts, curl\|bash, SSL disabled |
| P-43 | Container Security | Root containers, secrets in images |

### Mobile & Frontend
| P-44 | Flutter/Dart Security | Hardcoded keys, cert pinning, secure storage |
| P-45 | Mobile Network | Android cleartext, iOS ATS |
| P-46 | Webhook Ordering | Event persistence, dead-letter queues |
| P-47 | Financial Reconciliation | External balance comparison, compensation patterns |
| P-48 | React Frontend | dangerouslySetInnerHTML, localStorage tokens |
| P-49 | Git History Secrets | .env files, key files ever committed |

### Finance-Specific (Gold Standard)
| P-50 | Transaction Integrity | float/double for money, explicit RoundingMode, divide without scale |
| P-51 | Privilege Escalation | Unguarded role/permission mutations |
| P-52 | Timing Attacks | Constant-time comparison for secrets, .equals() on passwords |
| P-53 | Account Lifecycle | Account locking, email change verification |
| P-54 | API Key Management | Key expiration, permission scoping |
| P-55 | Crypto Address Security | Address validation, whitelisting, AML screening |
| P-56 | Multi-Signature Approval | Dual-approval workflows, Fireblocks co-signer/TAP |

### Compliance Gap Coverage (P-57 to P-64)
| # | Check | Framework Coverage |
|---|---|---|
| P-57 | Business Logic Abuse | OWASP API6:2023 — registration rate limits, bulk guards, bot detection |
| P-58 | Vulnerability Scan Evidence | PCI-DSS 11.3, CIS 7 — SAST/DAST configs, scan reports, CI integration |
| P-59 | Security Policy Docs | PCI-DSS 12.1, SOC 2 CC1.1, ISO A.5.1 — IR plan, DR plan, security policy |
| P-60 | Email Security | CIS 9.2, ISO A.8.21 — SPF/DKIM/DMARC, email injection |
| P-61 | Privacy & Consent | SOC 2 P1-P8, GDPR Art 6/7 — consent management, DSAR, data portability |
| P-62 | Pentest Evidence | PCI-DSS 11.4, CIS 18 — pentest reports, remediation tracking |
| P-63 | Supply Chain Risk | NIST GV.SC, CIS 15 — SBOM, dependency locking, vendor assessment |
| P-64 | Recovery Testing | SOC 2 A1.3, ISO A.8.14, NIST RC.RP — DR docs, backup config, health endpoints |

### Finance-Specific Extended Suite (P-65 to P-80)

These checks go beyond standard security frameworks into financial-system-specific behavioral controls. They cover the patterns that separate a secure application from a compliant financial institution.

| # | Check | What It Catches | Regulatory Basis |
|---|---|---|---|
| P-65 | Transaction Velocity | Rapid-fire transactions, structuring, cooling periods | BSA/AML, FinCEN |
| P-66 | Dormant Account Monitoring | Reactivation detection, step-up auth, login anomalies | FATF Rec 10, CDD Rule |
| P-67 | Cross-Account Transfers | Money mule detection, layering, beneficiary changes | AML 4th Directive |
| P-68 | Fee Manipulation | Negative fees, client-supplied fees, fee centralization | SOC 2 CC8.1 |
| P-69 | Exchange Rate Safety | Stale rates, rate bounds, spread limits, rate locking | MiFID II Best Execution |
| P-70 | Settlement Finality | No tx deletion, no status rewind, no qty zeroing, append-only | PSD2 Art 80, UCC 4A |
| P-71 | Beneficial Ownership | UBO tracking, entity KYC | FinCEN CDD Rule, 5AMLD |
| P-72 | Sanctions Screening | OFAC, PEP, country restrictions | OFAC Regulations, EU Sanctions |
| P-73 | Transaction Limits | Per-tx, rolling, atomic enforcement | BSA, Internal Controls |
| P-74 | Proof of Reserves | Balance reconciliation, overdraft prevention, double-entry | SOX 404, Basel III |
| P-75 | Audit Immutability | Audit triggers, append-only, actor attribution, integrity, retention | SOX 802, PCI 10.3, ISO A.8.15 |
| P-76 | Payment State Machine | Valid transitions, terminal states, expiration | PSD2, ISO 20022 |
| P-77 | Withdrawal Controls | Limits, address whitelist, cooldown, 2FA, manual review | Travel Rule, FATF Rec 16 |
| P-78 | Ledger Consistency | Atomic balance, drift detection, orphans, idempotent updates | GAAP, IFRS |
| P-79 | Regulatory Reporting | CTR readiness, SAR mechanism, regulatory export | BSA 31 CFR 1010.311 |
| P-80 | Financial Event Sourcing | Event log, history tables, point-in-time, data lineage | SOX 802, MiFID II |
| P-81 | Financial Input Guards | Negative amounts, overflow, type coercion, NaN/Infinity, zero-amount, precision | OWASP, PCI-DSS 6.5 |
| P-82 | Continuous Defense Model | Real-time monitoring, auto-response, audit automation, circuit breakers, self-healing | NIST CSF DE/RS |

### Compliance Evidence Verification (P-83 to P-95) — THE PATH TO 100%

These checks verify the existence of compliance artifacts that close the remaining gaps in all six frameworks. They transform Preston-Check from a code scanner into a compliance evidence verifier. Populate the compliance-template/ directory to satisfy these checks.

| # | Check | What It Verifies | Framework Gap Closed |
|---|---|---|---|
| P-83 | Physical Access Evidence | Physical security docs, badge system refs, data center documentation | PCI-DSS Req 9 |
| P-84 | Organizational Policies | Security policy, acceptable use, risk assessment, training, vendor mgmt, PCI scope | PCI-DSS Req 12 |
| P-85 | SOC 2 Availability | Capacity planning, SLA documentation, infrastructure redundancy | SOC 2 A1 |
| P-86 | SOC 2 Confidentiality | Data classification, NDA references, DLP controls | SOC 2 C1 |
| P-87 | ISO Organizational | ISMS scope, threat intelligence, supplier management, cloud security, incident mgmt | ISO 27001 A.5.x |
| P-88 | ISO People Controls | Screening, security training, offboarding procedures, remote work policy | ISO 27001 A.6.x |
| P-89 | ISO Physical Controls | Data center docs, equipment security, environmental monitoring | ISO 27001 A.7.x |
| P-90 | NIST Govern | Organizational context, risk strategy, roles, cybersecurity policy, supply chain | NIST CSF GV |
| P-91 | NIST Identify | Asset inventory, risk assessment, improvement tracking | NIST CSF ID |
| P-92 | NIST Recover | Recovery planning, recovery communication plan | NIST CSF RC |
| P-93 | CIS Asset Inventory | Service catalog, infrastructure-as-code, monitoring tools | CIS Control 1 |
| P-94 | CIS Security Training | Training docs, platform references, secure coding standards | CIS Control 14 |
| P-95 | CIS Service Provider & Pentest | Vendor assessments, pentest program, vulnerability scan schedule | CIS Controls 15, 18 |
