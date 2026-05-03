# Crypto Compliance Framework Mapping

This document maps each Preston-Check crypto check (P-301..P-360) to the
authoritative frameworks it satisfies. It serves two purposes: it lets
operators run framework-scoped scans (`preston-check --framework MiCA`),
and it gives auditors a clear evidence map from check findings to the
specific framework controls they cover.

The runner's `--framework` flag does a case-insensitive substring match
against each check's `frameworks` metadata field. Framework names below
match the canonical short codes used in metadata.

## OWASP Smart Contract Top 10 (2025)

Filter: `--framework "OWASP-SC-Top-10:2025"`

| Check | Sub-category |
|---|---|
| P-301 Reentrancy | SC05 |
| P-302 Integer Overflow | SC03 |
| P-303 tx.origin Authorization | SC02 |
| P-304 Unbounded Loops / Gas DoS | SC09 |
| P-305 DEX Slippage Protection | SC04 |
| P-306 Oracle Manipulation | SC07 |
| P-307 Unbounded Token Approvals | SC04 |
| P-308 Bridge Replay Protection | SC02 |
| P-310 Governance Time-Locks | SC01 |
| P-348 Proxy Upgrade Safety | SC01 |
| P-349 EIP-2612 Permit Replay | SC02 |
| P-350 ERC-4337 Account Abstraction Safety | SC02 |
| P-351 Access Control (Comprehensive) | SC01 |
| P-352 Flash Loan Attack Resistance | SC04 |
| P-353 Unchecked External Calls | SC07 |
| P-356 Liquidation Safety | SC02 |
| P-357 Token Admin Freeze Handling | SC04 |

## CryptoCurrency Security Standard v9.0 (CCSS)

Filter: `--framework CCSS` for all CCSS-mapped checks; or
`--framework "CCSS:9.0:Level1"` / `Level2` / `Level3` for tier-specific.

| Check | CCSS Level |
|---|---|
| P-311 Private Key / Mnemonic Exposure | Level 1 |
| P-312 HSM Integration | Level 2 |
| P-313 KMS-Only Key Operations | Level 2 |
| P-314 MPC / Threshold Signatures | Level 2 |
| P-315 Cold Wallet Air-Gap | Level 3 |
| P-316 Hot Wallet Concentration Limits | Level 2 |
| P-317 Key Ceremony Documentation | Level 1+ |
| P-318 Seed Phrase Handling Hygiene | Level 1 |
| P-319 Key Rotation Schedule | Level 2 |
| P-320 Multi-Sig Approval Discipline | Level 2 |
| P-344 Wallet Backup Encryption | Level 1 |
| P-345 Shamir's Secret Sharing | Level 3 |
| P-354 Cold-to-Hot Transfer Verification | Level 3 |
| P-358 CCSS Compliance Evidence | Level 1+ |

## FATF Recommendations and Travel Rule

Filter: `--framework FATF`

| Check | FATF Recommendation |
|---|---|
| P-322 Withdrawal Whitelist | Rec.16 |
| P-323 Pre-Send Risk Scoring | Rec.16 |
| P-324 OFAC SDN Live Screening | Rec.6 |
| P-327 Mixer Detection | Rec.16 |
| P-328 Travel Rule Compliance | Rec.16 |
| P-335 Counterparty Reputation | Rec.10 |
| P-336 Tainted Funds Source Trace | Rec.10 |

## OFAC and Sanctions

Filter: `--framework OFAC`

| Check | Mapping |
|---|---|
| P-323 Pre-Send Risk Scoring | OFAC:2024 |
| P-324 OFAC SDN Live Screening | OFAC:2024 |
| P-327 Mixer Detection | OFAC:2024 (mixer-sanctioning precedent) |
| P-328 Travel Rule | OFAC:2024 |
| P-336 Tainted Funds Trace | OFAC:2024 |

## EU MiCA / TFR

Filter: `--framework MiCA` or `--framework EU-TFR`

| Check | Mapping |
|---|---|
| P-316 Hot Wallet Concentration | MiCA:2024 (segregation, secure cold storage) |
| P-320 Multi-Sig Discipline | MiCA:2024 (authorization controls) |
| P-322 Withdrawal Whitelist | MiCA:2024 (custody segregation) |
| P-328 Travel Rule | EU-TFR:2023 (Transfer of Funds Regulation) |
| P-358 CCSS Evidence | MiCA:2024 (custody audit evidence) |

EU MiCA itself requires segregation, secure cold storage, multi-signature
wallets, strong key management, daily reconciliation, and regular audits;
the checks above touch each of those dimensions.

## NIST Cybersecurity Framework 2.0

Filter: `--framework NIST-CSF`

| Check | NIST-CSF Function:Category |
|---|---|
| P-312 HSM Integration | PR.DS |
| P-313 KMS-Only Operations | PR.DS |
| P-314 MPC / TSS | PR.DS |
| P-315 Cold Wallet Air-Gap | PR.DS |
| P-316 Hot Wallet Caps | PR.DS, DE.AE |
| P-317 Key Ceremony | GV.RM |
| P-319 Key Rotation | PR.DS |
| P-320 Multi-Sig | PR.AC |
| P-321 Address Validation | PR.DS |
| P-322 Withdrawal Whitelist | PR.AC |
| P-329 New-Address Cooldown | PR.AC |
| P-330 Step-Up Auth | PR.AC |
| P-331 Dust Attack Detection | DE.CM |
| P-335 Counterparty Reputation | DE.AE |
| P-337 Compromise Indicators | DE.AE |
| P-338 Approval Audit | PR.AC |
| P-339 Drainer Pattern Detection | DE.CM |
| P-340 Reorg Confirmation Depth | PR.DS |
| P-341 Hardware Wallet | PR.DS |
| P-342 Secure Enclave / TPM | PR.DS |
| P-343 BIP-44 Derivation | PR.DS |
| P-344 Backup Encryption | PR.DS |
| P-345 Shamir SSS | PR.DS |
| P-346 Memory Hygiene | PR.DS |
| P-354 Cold-to-Hot Verification | PR.AC |
| P-355 Blind Signing Prevention | PR.AC |
| P-359 Pause / Circuit Breaker | RS.MI |
| P-360 PQC Readiness | PR.DS |

## NIST Post-Quantum Cryptography (FIPS 203/204/205)

Filter: `--framework FIPS` or `--framework "NIST-FIPS"`

| Check | Mapping |
|---|---|
| P-360 PQC Readiness Assessment | NIST-FIPS:203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) |

## OWASP Mobile Application Security Verification Standard 2.0

Filter: `--framework OWASP-MASVS`

| Check | MASVS Control |
|---|---|
| P-342 Secure Enclave / TPM | CRYPTO-1 |
| P-344 Wallet Backup Encryption | CRYPTO-2 |
| P-355 Blind Signing Prevention | AUTH-2 |

## OWASP API Security Top 10 (2023)

Filter: `--framework OWASP-API`

| Check | API Top 10 Item |
|---|---|
| P-311 Private Key Exposure | API8 |
| P-318 Seed Phrase Handling | API8 |
| P-321 Address Validation | API3 |
| P-326 Address Poisoning Detection | API3 |
| P-338 Approval Audit | API3 |

## ISO 27001:2022

Filter: `--framework ISO-27001`

| Check | Annex A Control |
|---|---|
| P-312 HSM Integration | A.10.1 |
| P-313 KMS-Only Operations | A.10.1 |
| P-315 Cold Wallet Air-Gap | A.10.1 |
| P-318 Seed Phrase Handling | A.8.10 |
| P-319 Key Rotation | A.10.1 |
| P-320 Multi-Sig | A.5.16 |
| P-322 Withdrawal Whitelist | A.5.16 |
| P-329 New-Address Cooldown | A.5.16 |
| P-330 Step-Up Auth | A.5.17 |

## PCI-DSS v4.0

Filter: `--framework PCI-DSS`

| Check | PCI Requirement |
|---|---|
| P-311 Private Key Exposure | 3.5 |
| P-318 Seed Phrase Handling | 3.5 |
| P-313 KMS-Only Operations | 3.6 |
| P-319 Key Rotation | 3.6 |
| P-344 Wallet Backup Encryption | 3.5 |

## SOC 2 Trust Service Criteria (2017)

Filter: `--framework SOC2`

| Check | TSC |
|---|---|
| P-317 Key Ceremony | CC6.1 |

## PSD2 (EU Payment Services Directive 2)

Filter: `--framework PSD2`

| Check | Article |
|---|---|
| P-330 Step-Up Auth | Art.97 (SCA) |

## FinCEN

Filter: `--framework FinCEN`

| Check | Citation |
|---|---|
| P-323 Pre-Send Risk Scoring | 31CFR1010 |
| P-328 Travel Rule | 31CFR1010.410 |
| P-336 Tainted Funds Trace | 31CFR1010 |

## NIST Secure Software Development Framework

Filter: `--framework NIST-SSDF`

| Check | SSDF Practice |
|---|---|
| P-301 Reentrancy | PW.7 |

## Compliance run-recipes

For an EU MiCA-focused custody audit dry-run:

```bash
preston-check --framework MiCA --report mica-audit.md --config configs/myapp.yml
```

For CCSS Level 2 self-assessment:

```bash
preston-check --framework "CCSS:9.0:Level2" --report ccss-l2.md
```

For an OWASP Smart Contract Top 10 (2025) review:

```bash
preston-check --framework "OWASP-SC-Top-10:2025" --report owasp-sc.md
```

For comprehensive sanctions and Travel Rule compliance:

```bash
preston-check --framework FATF --report fatf-compliance.md
preston-check --framework OFAC --report ofac-compliance.md
```

Note that filters are case-insensitive substrings against the
`frameworks` metadata field. A filter like `MiCA` matches any check
whose metadata mentions `MiCA:2024` or future versions; a filter like
`CCSS:9.0:Level2` matches only checks pinned to that specific level.
This means the same operator command continues to work as new framework
versions land — the catalog stays scoped to the latest references the
checks declare.
