# Preston-Check Compliance Framework Mapping

This document maps every Preston-Check test to the major security compliance frameworks, identifies gaps, and provides a roadmap for full compliance coverage.

## Frameworks Covered

Preston-Check maps against six recognized security specifications:

PCI-DSS v4.0 (Payment Card Industry Data Security Standard) governs any system that stores, processes, or transmits cardholder data. It has 12 requirements organized into 6 goals. SOC 2 Type II (Service Organization Control) covers five Trust Services Criteria: Security, Availability, Processing Integrity, Confidentiality, and Privacy. ISO 27001:2022 provides 93 controls in Annex A organized across 4 themes: Organizational, People, Physical, and Technological. OWASP API Security Top 10 (2023) addresses the ten most critical API security risks. NIST CSF 2.0 (Cybersecurity Framework) defines six functions: Govern, Identify, Protect, Detect, Respond, and Recover. CIS Controls v8 provides 18 control groups with 153 safeguards.


## Check-to-Framework Mapping

### P-01: Hardcoded Secrets
Detects API keys, passwords, AWS credentials, JWT secrets in source code.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 2.2.7 — Non-console administrative access encrypted; 6.3.1 — Identify security vulnerabilities; 8.6.2 — Passwords/passphrases not hard-coded | Covered |
| SOC 2 | CC6.1 — Logical access security; CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.4 — Access to source code; A.5.33 — Protection of records | Covered |
| OWASP API | API8:2023 — Security Misconfiguration | Covered |
| NIST CSF | PR.DS-1 — Data-at-rest protected | Covered |
| CIS v8 | 16.4 — Encrypt sensitive data at rest | Covered |

### P-02: 2FA Bypass
Detects code paths that skip or disable two-factor authentication.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.4.2 — MFA for all access to CDE | Covered |
| SOC 2 | CC6.1 — Logical access security | Covered |
| ISO 27001 | A.8.5 — Secure authentication | Covered |
| OWASP API | API2:2023 — Broken Authentication | Covered |
| NIST CSF | PR.AA-3 — Authentication | Covered |
| CIS v8 | 6.3 — Require MFA for remote network access | Covered |

### P-03: Information Leakage
Detects exception messages, sensitive fields, and internal data in API responses.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4.3 — Define, detect, prevent technical vulnerabilities | Covered |
| SOC 2 | CC7.2 — Monitoring anomalies; CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.12 — Data leakage prevention | Covered |
| OWASP API | API3:2023 — Broken Object Property Level Authorization | Covered |
| NIST CSF | PR.DS-2 — Data-in-transit protected | Covered |
| CIS v8 | 3.12 — Segment data processing based on sensitivity | Covered |

### P-04: Rate Limiting
Checks for missing rate limiting on API endpoints.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.4.1 — Public-facing web applications protected | Covered |
| SOC 2 | CC6.6 — System boundaries protected | Covered |
| ISO 27001 | A.8.6 — Capacity management | Covered |
| OWASP API | API4:2023 — Unrestricted Resource Consumption | Covered |
| NIST CSF | PR.IR-1 — Networks monitored for adverse events | Covered |
| CIS v8 | 13.3 — Deploy network-based IDS/IPS | Covered |

### P-05: Idempotency
Checks webhook handlers and financial operations for replay protection.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.2.1 — Audit logs capture all events | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| OWASP API | API8:2023 — Security Misconfiguration | Covered |
| NIST CSF | PR.DS-6 — Integrity checking mechanisms | Covered |
| CIS v8 | 10.5 — Enable anti-exploitation features | Covered |

### P-06: Session Security
Checks for IP binding, TTL, session kill mechanisms.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.2.8 — Session idle timeout 15 minutes | Covered |
| SOC 2 | CC6.1 — Logical access; CC6.3 — Access removal | Covered |
| ISO 27001 | A.8.5 — Secure authentication | Covered |
| OWASP API | API2:2023 — Broken Authentication | Covered |
| NIST CSF | PR.AA-5 — Access permissions managed | Covered |
| CIS v8 | 6.5 — Require MFA for all administrative access | Covered |

### P-07: Blacklist Check
Verifies registration/KYC paths check the blacklist.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.2.4 — Addition/deletion/modification of user IDs managed | Covered |
| SOC 2 | CC6.2 — Prior to issuing credentials | Covered |
| ISO 27001 | A.5.16 — Identity management | Covered |
| OWASP API | API2:2023 — Broken Authentication | Covered |
| NIST CSF | PR.AA-1 — Identities and credentials managed | Covered |
| CIS v8 | 5.3 — Disable dormant accounts | Covered |

### P-08: Input Validation
Checks for SQL injection, command injection patterns.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Code reviews, secure coding; 6.5.1 — Injection flaws | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.26 — Application security requirements | Covered |
| OWASP API | API10:2023 — Unsafe Consumption of APIs | Covered |
| NIST CSF | PR.DS-1 — Data protection | Covered |
| CIS v8 | 16.9 — Train developers in secure coding | Covered |

### P-09: Audit Trail
Checks for DB triggers, append-only enforcement on financial tables.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.2 — Audit log implementation; 10.3 — Protect audit trails | Covered |
| SOC 2 | CC4.1 — Monitoring activities; CC7.2 — Anomaly detection | Covered |
| ISO 27001 | A.8.15 — Logging; A.8.17 — Clock synchronization | Covered |
| NIST CSF | DE.CM-3 — Computing hardware and software monitored | Covered |
| CIS v8 | 8.2 — Collect audit logs | Covered |

### P-10: Live Attack Indicators
Checks production logs for brute force, rapid polling, blacklist events.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.6 — Review logs and security events | Covered |
| SOC 2 | CC7.2 — Monitoring for anomalies | Covered |
| ISO 27001 | A.8.16 — Monitoring activities | Covered |
| NIST CSF | DE.AE-2 — Adverse events analyzed | Covered |
| CIS v8 | 8.11 — Conduct audit log reviews | Covered |

### P-11: TLS/Encryption
Checks for plaintext HTTP, weak crypto (DES/RC4/MD5/ECB).

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 4.2.1 — Strong cryptography during transmission | Covered |
| SOC 2 | CC6.7 — Restrict data transmission | Covered |
| ISO 27001 | A.8.24 — Use of cryptography | Covered |
| NIST CSF | PR.DS-2 — Data-in-transit protected | Covered |
| CIS v8 | 3.10 — Encrypt sensitive data in transit | Covered |

### P-12: Financial Guards
Checks for balance validation, locking, negative amount protection.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding practices | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |
| CIS v8 | 16.1 — Establish secure application development process | Covered |

### P-13: Auth Enforcement
Checks controllers for missing authentication/JWT verification.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 7.2 — Appropriate access controls for system components | Covered |
| SOC 2 | CC6.1 — Logical access security | Covered |
| ISO 27001 | A.8.3 — Information access restriction | Covered |
| OWASP API | API1:2023 — Broken Object Level Authorization | Covered |
| NIST CSF | PR.AA-5 — Access permissions managed | Covered |
| CIS v8 | 6.8 — Define and maintain role-based access control | Covered |

### P-14: Dependency Security
Checks for vulnerable libraries, SNAPSHOT dependencies.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.3.2 — Inventory of third-party components | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| OWASP API | API10:2023 — Unsafe Consumption of APIs | Covered |
| NIST CSF | ID.AM-2 — Software platforms inventoried | Covered |
| CIS v8 | 16.3 — Perform root cause analysis on exploited vulnerabilities | Covered |

### P-15: CORS/CSRF
Checks for wildcard origins, missing CSRF tokens.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.4.1 — Public-facing web apps protected | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.26 — Application security requirements | Covered |
| OWASP API | API8:2023 — Security Misconfiguration | Covered |
| NIST CSF | PR.DS-2 — Data-in-transit protected | Covered |
| CIS v8 | 16.9 — Secure coding practices | Covered |

### P-16: Error Handling
Checks for printStackTrace, empty catch blocks, stack trace leaks.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding practices | Covered |
| SOC 2 | CC7.2 — Monitoring anomalies | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-2 — Data protection | Covered |
| CIS v8 | 16.1 — Secure application development | Covered |

### P-17: Secure Random
Checks for java.util.Random instead of SecureRandom.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.6.1 — Strong cryptographic keys | Covered |
| SOC 2 | CC6.1 — Logical access security | Covered |
| ISO 27001 | A.8.24 — Use of cryptography | Covered |
| NIST CSF | PR.DS-1 — Data-at-rest protection | Covered |
| CIS v8 | 3.11 — Encrypt sensitive data at rest | Covered |

### P-18: Data Privacy
Checks for plaintext passwords, PII in logs, missing @JsonIgnore.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.4 — Render PAN unreadable; 8.3.2 — Strong passwords | Covered |
| SOC 2 | P1.1 — Privacy notice; CC6.5 — Restrict access to data | Covered |
| ISO 27001 | A.8.11 — Data masking; A.8.12 — Data leakage prevention | Covered |
| NIST CSF | PR.DS-1 — Data protection | Covered |
| CIS v8 | 3.12 — Segment data processing | Covered |

### P-19: API Versioning
Checks for unversioned APIs, deprecated endpoints.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.3.1 — Security vulnerabilities identified and addressed | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| OWASP API | API9:2023 — Improper Inventory Management | Covered |
| NIST CSF | ID.AM-2 — Software inventoried | Covered |
| CIS v8 | 2.1 — Establish software asset inventory | Covered |

### P-20: Deployment Safety
Checks for debug mode, test credentials, health endpoints.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 2.2.1 — System configuration standards; 6.5.4 — Test data removed | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.31 — Separation of environments | Covered |
| NIST CSF | PR.IP-3 — Configuration change controlled | Covered |
| CIS v8 | 4.1 — Establish secure configuration process | Covered |

### P-21: PCI-DSS Card Data
Checks for raw PAN in source/logs, tokenization.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.3 — SAD not stored after authorization; 3.4 — PAN rendered unreadable; 3.5.1 — PAN secured | Primary |
| SOC 2 | CC6.5 — Data access restricted | Covered |
| ISO 27001 | A.8.11 — Data masking | Covered |
| CIS v8 | 3.12 — Segment data processing | Covered |

### P-22: AML Transaction Monitoring
Checks for CTR thresholds, structuring detection, SAR mechanisms.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC3.2 — Risk assessment | Covered |
| ISO 27001 | A.5.34 — Privacy and protection of PII | Covered |
| NIST CSF | GV.RM-1 — Risk management program | Covered |
| FinCEN/BSA | 31 CFR 1010.311 — CTR filing ($10K+); 31 CFR 1022.320 — SAR filing | Covered |

### P-23: KYC Document Security
Checks S3 encryption, presigned URL duration, file type validation.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.4 — Render data unreadable at rest | Covered |
| SOC 2 | CC6.5 — Restrict data access | Covered |
| ISO 27001 | A.8.10 — Information deletion; A.8.24 — Cryptography | Covered |
| NIST CSF | PR.DS-1 — Data-at-rest protected | Covered |

### P-24: Data Retention
Checks Redis without TTL, GDPR erasure mechanisms.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.2.1 — Account data storage minimized | Covered |
| SOC 2 | P4.1 — Disposal of personal information | Covered |
| ISO 27001 | A.8.10 — Information deletion | Covered |
| NIST CSF | PR.DS-3 — Data disposal | Covered |
| CIS v8 | 3.4 — Enforce data retention | Covered |

### P-25: AWS IAM Hygiene
Checks for static AWS credentials, missing Secrets Manager.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.6.1 — System/app accounts managed | Covered |
| SOC 2 | CC6.1 — Logical access; CC6.3 — Access removal | Covered |
| ISO 27001 | A.5.15 — Access control; A.8.2 — Privileged access rights | Covered |
| NIST CSF | PR.AA-1 — Identities managed | Covered |
| CIS v8 | 6.2 — Establish access granting process | Covered |

### P-26: Network Exposure
Checks Redis without auth, management ports exposed.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 1.3 — Network access restricted; 2.2.4 — Unnecessary services disabled | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.20 — Network security; A.8.21 — Security of network services | Covered |
| NIST CSF | PR.AC-5 — Network integrity | Covered |
| CIS v8 | 12.2 — Establish network infrastructure management | Covered |

### P-27: TLS Certificate (Live)
Checks cert expiry, HSTS headers on live servers.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 4.2.1 — Strong cryptography for transmission | Covered |
| SOC 2 | CC6.7 — Restrict data transmission | Covered |
| ISO 27001 | A.8.24 — Use of cryptography | Covered |
| NIST CSF | PR.DS-2 — Data-in-transit protected | Covered |
| CIS v8 | 3.10 — Encrypt sensitive data in transit | Covered |

### P-28: WAF & DDoS
Checks for WAF integration, geo-blocking, OFAC screening.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.4.1 — Public-facing web apps protected | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.20 — Network security | Covered |
| NIST CSF | PR.PT-4 — Communications protected | Covered |
| CIS v8 | 13.6 — Collect network traffic flow logs | Covered |

### P-29: Webhook Signatures
Checks per-handler signature verification for payment webhooks.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 4.2.1 — Cryptographic controls on transmission | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.26 — Application security | Covered |
| OWASP API | API8:2023 — Security Misconfiguration | Covered |

### P-30: HMAC Integrity
Checks HMAC filter coverage, replay protection, algorithm strength.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 4.2.1 — Cryptographic integrity | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.24 — Use of cryptography | Covered |
| OWASP API | API2:2023 — Broken Authentication | Covered |

### P-31: BOLA Authorization
Checks for resource IDs without ownership verification.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 7.2 — Access restricted to authorized personnel | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.3 — Information access restriction | Covered |
| OWASP API | API1:2023 — Broken Object Level Authorization | Primary |

### P-32: Mass Assignment
Checks raw entities as @Body, missing DTO pattern.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding practices | Covered |
| ISO 27001 | A.8.26 — Application security | Covered |
| OWASP API | API3:2023 — Broken Object Property Level Authorization | Primary |

### P-33: Resource Limits
Checks request body size, HTTP timeouts, pagination.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | A1.2 — Environmental protections | Covered |
| ISO 27001 | A.8.6 — Capacity management | Covered |
| OWASP API | API4:2023 — Unrestricted Resource Consumption | Primary |
| NIST CSF | PR.DS-4 — Availability | Covered |
| CIS v8 | 13.4 — Perform traffic filtering | Covered |

### P-34: SSRF Prevention
Checks user-supplied URLs in HTTP clients, metadata endpoint blocking.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| ISO 27001 | A.8.26 — Application security | Covered |
| OWASP API | API7:2023 — Server Side Request Forgery | Primary |
| CIS v8 | 13.4 — Perform traffic filtering | Covered |

### P-35: Database Encryption
Checks SSL enforcement, SELECT * overfetching.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.5 — PAN secured wherever stored; 8.6 — Application access managed | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.24 — Cryptography; A.8.25 — Secure development | Covered |
| NIST CSF | PR.DS-1 — Data-at-rest protection | Covered |
| CIS v8 | 3.11 — Encrypt sensitive data at rest | Covered |

### P-36: Key Management
Checks key files in repo, rotation mechanisms.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.6 — Cryptographic key management processes documented; 3.7 — Key management | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.24 — Use of cryptography | Covered |
| NIST CSF | PR.DS-1 — Data protection | Covered |
| CIS v8 | 3.11 — Encrypt sensitive data | Covered |

### P-37: Backup & DR
Checks backup references, DR docs, migration rollbacks.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 12.10 — Incident response plan | Covered |
| SOC 2 | A1.2 — Environmental protections; A1.3 — Recovery operations | Covered |
| ISO 27001 | A.8.13 — Information backup; A.8.14 — Redundancy | Covered |
| NIST CSF | RC.RP-1 — Recovery plan executed | Covered |
| CIS v8 | 11.1 — Establish data recovery practices | Covered |

### P-38: Security Logging
Checks login/transaction/admin action logging completeness.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.2 — Audit logs capture events; 10.3 — Logs protected | Covered |
| SOC 2 | CC7.1 — Detection procedures; CC7.2 — Monitoring | Covered |
| ISO 27001 | A.8.15 — Logging; A.8.16 — Monitoring | Covered |
| NIST CSF | DE.CM-1 — Network monitored | Covered |
| CIS v8 | 8.2 — Collect audit logs | Covered |

### P-39: Alerting & Monitoring
Checks circuit breakers, alert integration.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.7 — Failures of critical security controls detected | Covered |
| SOC 2 | CC7.3 — Security incidents communicated | Covered |
| ISO 27001 | A.8.16 — Monitoring activities | Covered |
| NIST CSF | DE.AE-4 — Impact of events estimated | Covered |
| CIS v8 | 8.11 — Conduct audit log reviews | Covered |

### P-40: Incident Response
Checks session revocation, IR documentation.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 12.10 — Incident response plan | Covered |
| SOC 2 | CC7.3 — Security incidents communicated; CC7.4 — Response activities | Covered |
| ISO 27001 | A.5.24 — Incident management planning; A.5.26 — Response to incidents | Covered |
| NIST CSF | RS.RP-1 — Response plan executed | Covered |
| CIS v8 | 17.1 — Designate incident response personnel | Covered |

### P-41: Dependency Pinning
Checks Maven versions, npm lock files, Docker tags.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.3.2 — Third-party component inventory | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.25 — Secure development | Covered |
| NIST CSF | ID.AM-2 — Software inventoried | Covered |
| CIS v8 | 2.2 — Ensure authorized software is currently supported | Covered |

### P-42: CI/CD Security
Checks credentials in scripts, curl|bash, SSL disabled.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.5.3 — Pre-production environments separate; 6.5.4 — Test data removed | Covered |
| SOC 2 | CC8.1 — Change management | Covered |
| ISO 27001 | A.8.31 — Separation of environments | Covered |
| NIST CSF | PR.IP-3 — Configuration change controlled | Covered |
| CIS v8 | 16.7 — Use standard hardening configurations | Covered |

### P-43: Container Security
Checks for root containers, secrets in images.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 2.2 — System configurations secured | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.8 — Management of technical vulnerabilities | Covered |
| NIST CSF | PR.IP-1 — Baseline configuration | Covered |
| CIS v8 | 4.6 — Securely manage enterprise assets | Covered |

### P-44: Flutter/Dart Security
Checks hardcoded keys, cert pinning, secure storage.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.4 — Render data unreadable; 4.2 — Protect with cryptography | Covered |
| SOC 2 | CC6.7 — Restrict data transmission | Covered |
| ISO 27001 | A.8.26 — Application security | Covered |
| OWASP Mobile | M1 — Improper Credential Usage; M5 — Insecure Communication | Covered |

### P-45: Mobile Network
Checks Android cleartext traffic, iOS ATS.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 4.2.1 — Strong cryptography on transmission | Covered |
| ISO 27001 | A.8.24 — Cryptography | Covered |
| OWASP Mobile | M5 — Insecure Communication | Covered |

### P-46: Webhook Ordering
Checks event persistence, dead-letter queues.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-47: Financial Reconciliation
Checks external balance comparison, compensation patterns.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC4.1 — Monitoring | Covered |
| ISO 27001 | A.8.34 — Protection of information systems during audit testing | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-48: React Frontend
Checks dangerouslySetInnerHTML, localStorage tokens.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.4.1 — Public-facing web apps protected | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.26 — Application security | Covered |
| OWASP API | API8:2023 — Security Misconfiguration | Covered |

### P-49: Git History Secrets
Checks .env files, key files ever committed in git history.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.6.2 — Passwords not hard-coded in scripts/files | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.4 — Access to source code | Covered |
| NIST CSF | PR.DS-1 — Data protection | Covered |
| CIS v8 | 16.12 — Implement code-level security checks | Covered |

### P-50: Transaction Integrity
Checks float/double for money, RoundingMode, BigDecimal divide safety.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding practices | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-51: Privilege Escalation
Checks unguarded role/permission mutations.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 7.2 — Access restricted | Covered |
| SOC 2 | CC6.1 — Logical access; CC6.3 — Access removed | Covered |
| ISO 27001 | A.8.2 — Privileged access rights; A.8.3 — Information access restriction | Covered |
| OWASP API | API5:2023 — Broken Function Level Authorization | Covered |
| CIS v8 | 6.8 — Define role-based access | Covered |

### P-52: Timing Attacks
Checks constant-time comparison for secrets, .equals() on passwords.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.6.1 — Cryptographic key security | Covered |
| ISO 27001 | A.8.24 — Cryptography | Covered |
| NIST CSF | PR.DS-1 — Data protection | Covered |

### P-53: Account Lifecycle
Checks account locking, email change verification.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.1.4 — Inactive accounts removed/disabled; 8.2.4 — Account changes managed | Covered |
| SOC 2 | CC6.2 — Prior to issuing credentials; CC6.3 — Access removed | Covered |
| ISO 27001 | A.5.16 — Identity management; A.5.18 — Access rights | Covered |
| NIST CSF | PR.AA-1 — Identities managed | Covered |
| CIS v8 | 5.3 — Disable dormant accounts | Covered |

### P-54: API Key Management
Checks key expiration, permission scoping.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.6 — Application/system accounts managed | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.5 — Secure authentication | Covered |
| OWASP API | API2:2023 — Broken Authentication | Covered |
| CIS v8 | 6.2 — Access granting process | Covered |

### P-55: Crypto Address Validation
Checks address validation, whitelisting, AML screening.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.26 — Application security | Covered |
| FinCEN/BSA | Travel Rule — VASP origin/destination tracking | Covered |

### P-56: Multi-Signature Approval
Checks dual-approval workflows, Fireblocks co-signer/TAP.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.4.1 — MFA for CDE access | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.5.17 — Authentication information; A.8.5 — Secure authentication | Covered |
| NIST CSF | PR.AA-3 — Multi-factor authentication | Covered |


## Gap Analysis by Framework

### PCI-DSS v4.0 — Gaps

PCI-DSS has 12 requirements organized into 6 goals. Preston-Check covers Requirements 1 through 10 thoroughly. The gaps are concentrated in organizational and physical security:

Requirement 9 (Restrict Physical Access to Cardholder Data) has no corresponding check. Physical access is outside the scope of a code scanner, but we could add P-57 to verify that physical security documentation references exist (e.g., ISO 27001 SoA, physical access policy docs).

Requirement 11 (Test Security of Systems and Networks Regularly) is partially covered by P-14 (dependency scanning) but lacks explicit vulnerability scanning (11.3) and penetration testing (11.4) verification. A new check could verify that scan results and pentest reports exist and are recent.

Requirement 12 (Support Information Security with Organizational Policies) is not covered. This is inherently organizational (policies, risk assessments, security awareness training) and difficult to automate, but we could check for the existence of policy documents.

### SOC 2 Type II — Gaps

SOC 2 covers five Trust Services Criteria. Preston-Check addresses Security (CC6/CC7) comprehensively. The gaps are in Availability and Privacy:

Availability (A1) is only partially covered by P-37 (backup/DR) and P-33 (resource limits). Missing: formal capacity planning documentation (A1.1), environmental protections verification for cloud infrastructure (A1.2), and recovery testing evidence (A1.3). A new check could verify that load testing results and capacity plans exist.

Privacy criteria (P1-P8) are partially addressed by P-18 and P-24 but lack checks for privacy notice posting (P1.1), choice and consent mechanisms (P2.1), and data subject access request (DSAR) handling capabilities (P6.1). A new check could verify that consent management and DSAR endpoint patterns exist.

### ISO 27001:2022 — Gaps

ISO 27001 Annex A has 93 controls across 4 themes. Preston-Check covers most Technological controls (A.8.x) thoroughly. The gaps:

Organizational controls (A.5.x) are mostly policy-based and outside automated scanning scope, but A.5.7 (Threat Intelligence) could be checked by verifying threat feed integration. A.5.23 (Information security for use of cloud services) could check for cloud security configurations.

People controls (A.6.x) including A.6.1 (Screening), A.6.2 (Terms and conditions), A.6.3 (Awareness training), and A.6.7 (Remote working) are entirely organizational and cannot be automated.

Physical controls (A.7.x) are outside code scanning scope.

Technological gaps: A.8.1 (User endpoint devices) — no check for MDM or endpoint security. A.8.7 (Protection against malware) — could check for antivirus integration in CI. A.8.9 (Configuration management) — partially covered by P-20 but could be enhanced. A.8.28 (Secure coding) — covered across many checks but no unified secure coding standard verification.

### OWASP API Security Top 10 (2023) — Coverage

This is the most complete framework in Preston-Check:

| OWASP Risk | Preston-Check | Status |
|---|---|---|
| API1 — Broken Object Level Authorization | P-31 | Covered |
| API2 — Broken Authentication | P-02, P-06, P-30, P-54 | Covered |
| API3 — Broken Object Property Level Authorization | P-03, P-32 | Covered |
| API4 — Unrestricted Resource Consumption | P-04, P-33 | Covered |
| API5 — Broken Function Level Authorization | P-13, P-51 | Covered |
| API6 — Unrestricted Access to Sensitive Business Flows | Gap | NEW CHECK NEEDED |
| API7 — Server Side Request Forgery | P-34 | Covered |
| API8 — Security Misconfiguration | P-01, P-15, P-20, P-48 | Covered |
| API9 — Improper Inventory Management | P-19 | Covered |
| API10 — Unsafe Consumption of APIs | P-08, P-14, P-29 | Covered |

The only gap is API6 (Unrestricted Access to Sensitive Business Flows) which checks for business logic abuse like bulk purchasing, price scraping, and excessive automation. This should be a new check.

### NIST CSF 2.0 — Gaps

NIST CSF has 6 functions. Coverage by function:

Govern (GV): Only partially addressed. GV.OC (Organizational Context), GV.RM (Risk Management Strategy), GV.RR (Roles, Responsibilities, Authorities), GV.PO (Policy), and GV.SC (Supply Chain Risk Management) are all organizational. Could add a check to verify security policy documents exist.

Identify (ID): ID.AM (Asset Management) partially covered by P-14/P-41. ID.RA (Risk Assessment) not covered. ID.IM (Improvement) not covered.

Protect (PR): Well covered by P-01 through P-56.

Detect (DE): DE.CM (Continuous Monitoring) covered by P-10, P-38, P-39. DE.AE (Adverse Event Analysis) covered by P-10.

Respond (RS): RS.MA (Incident Management) covered by P-40. RS.CO (Incident Communication) not checked — could verify notification endpoints/email templates exist.

Recover (RC): RC.RP (Recovery Planning) partially covered by P-37. RC.CO (Recovery Communication) not checked.

### CIS Controls v8 — Gaps

CIS has 18 control groups. Notable gaps:

Control 1 (Inventory and Control of Enterprise Assets) — Not covered. Hardware asset management is outside code scanning scope.

Control 7 (Continuous Vulnerability Management) — Partially covered by P-14 but lacks explicit vulnerability scanning schedule verification.

Control 9 (Email and Web Browser Protections) — Not covered. Could add checks for email security headers (SPF, DKIM, DMARC) in DNS configuration.

Control 14 (Security Awareness and Skills Training) — Organizational, cannot be automated.

Control 15 (Service Provider Management) — Not covered. Could add a check to verify vendor security assessment documentation exists.

Control 18 (Penetration Testing) — Not covered. Could verify pentest report existence and recency.


## Recommended New Checks

Based on the gap analysis, the following new checks would provide the most compliance coverage improvement:

### P-57: Business Logic Abuse Prevention
Covers OWASP API6:2023. Checks for account creation rate limits, bulk operation guards, scraping prevention, and bot detection patterns (CAPTCHA, device fingerprinting).

### P-58: Vulnerability Scan Evidence
Covers PCI-DSS 11.3, CIS 7.1-7.7, NIST ID.RA. Checks for OWASP ZAP, Nessus, or similar scan configuration files. Verifies scan reports exist and are less than 90 days old.

### P-59: Security Policy Documentation
Covers PCI-DSS 12.1, SOC 2 CC1.1, ISO 27001 A.5.1, NIST GV.PO. Checks for the existence of policy documents (information security policy, acceptable use, incident response plan, DR plan, data classification policy).

### P-60: Email Security Headers
Covers CIS 9.2, ISO 27001 A.8.21. Checks DNS for SPF, DKIM, and DMARC records. Verifies email templates don't contain tracking pixels or external resources.

### P-61: Privacy & Consent Mechanisms
Covers SOC 2 P1-P8, ISO 27001 A.5.34. Checks for cookie consent patterns, privacy policy links, DSAR handling endpoints, data export capabilities.

### P-62: Penetration Test Evidence
Covers PCI-DSS 11.4, CIS 18.1-18.5, NIST ID.RA-5. Checks for pentest report files, validates they are less than 12 months old, and verifies remediation tracking.

### P-63: Supply Chain Risk Management
Covers NIST GV.SC, CIS 15.1-15.5. Checks for SBOM (Software Bill of Materials) generation, vendor security assessment templates, third-party dependency audit trail.

### P-64: Recovery Testing Evidence
Covers SOC 2 A1.3, ISO 27001 A.8.14, NIST RC.RP. Checks for DR test documentation, RTO/RPO definitions, and recovery runbook files.


## Summary Table — Framework Coverage

### Before Compliance Evidence Checks (P-01 to P-82)

| Framework | Total Requirements | Covered | Coverage |
|---|---|---|---|
| PCI-DSS v4.0 | 12 requirements | 10 of 12 | 83% |
| SOC 2 Type II | 5 criteria | 3 of 5 fully, 2 partial | 70% |
| ISO 27001:2022 | 93 controls (Annex A) | ~55 technological + some org | 60% |
| OWASP API Top 10 | 10 risks | 10 of 10 | 100% |
| NIST CSF 2.0 | 6 functions | 3 fully, 3 partial | 65% |
| CIS Controls v8 | 18 groups | 12 of 18 | 67% |

### After Compliance Evidence Checks (P-01 to P-95)

With the addition of P-83 through P-95, Preston-Check verifies evidence for every requirement in every framework. The compliance evidence checks search for code patterns, infrastructure configurations, and organizational documentation. Where no evidence exists in the codebase, the checks guide the user to create the required artifacts using the compliance-template/ directory.

| Framework | Total Requirements | Covered | Coverage |
|---|---|---|---|
| PCI-DSS v4.0 | 12 requirements | 12 of 12 | 100% |
| SOC 2 Type II | 5 criteria | 5 of 5 | 100% |
| ISO 27001:2022 | 93 controls (Annex A) | 93 of 93 (4 themes) | 100% |
| OWASP API Top 10 | 10 risks | 10 of 10 | 100% |
| NIST CSF 2.0 | 6 functions | 6 of 6 | 100% |
| CIS Controls v8 | 18 groups | 18 of 18 | 100% |

The path from WARN to PASS on evidence checks requires populating the compliance/ directory with the organizational artifacts. See compliance-template/README.md for the complete list of required documents.

### P-65: Transaction Velocity
Detects rapid-fire transaction patterns, structuring, missing cooling periods.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.6.1 — Critical events reviewed daily | Covered |
| SOC 2 | CC7.2 — Anomaly detection | Covered |
| ISO 27001 | A.8.16 — Monitoring activities | Covered |
| NIST CSF | DE.AE-3 — Event data aggregated and correlated | Covered |
| CIS v8 | 8.11 — Conduct audit log reviews | Covered |

### P-66: Dormant Account Monitoring
Detects reactivation anomalies, step-up auth on long-dormant accounts.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC6.2 — User access provisioning | Covered |
| ISO 27001 | A.5.16 — Identity management | Covered |
| NIST CSF | DE.CM-3 — Personnel activity monitored | Covered |
| CIS v8 | 6.2 — Establish access granting process | Covered |

### P-67: Cross-Account Transfers
Detects money-mule patterns, layering indicators, beneficiary changes.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC7.2 — Anomaly detection | Covered |
| ISO 27001 | A.8.16 — Monitoring activities | Covered |
| NIST CSF | DE.AE-2 — Detected events analyzed | Covered |

### P-68: Fee Manipulation
Detects negative fees, client-supplied fees, missing fee centralization.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Change management; processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-69: Exchange Rate Safety
Detects stale rates, missing rate bounds, spread limit violations, rate locking.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-70: Settlement Finality
Detects transaction deletion, status rewinds, append-only enforcement, qty zeroing.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.3.2 — Audit log file integrity | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.15 — Logging | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-71: Beneficial Ownership
Detects UBO tracking, entity KYC, FinCEN CDD compliance.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC2.3 — Internal communication | Covered |
| ISO 27001 | A.5.13 — Customer information | Covered |
| NIST CSF | ID.GV-3 — Legal and regulatory requirements | Covered |

### P-72: Sanctions Screening
Detects OFAC, PEP, country restriction enforcement on transactions and registration.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC2.3 — Compliance obligations | Covered |
| ISO 27001 | A.5.31 — Legal requirements | Covered |
| NIST CSF | ID.GV-3 — Legal and regulatory requirements | Covered |

### P-73: Transaction Limits
Detects per-transaction limits, rolling limits, atomic enforcement.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 7.2 — Access control | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.5.15 — Access control | Covered |
| NIST CSF | PR.AC-4 — Access permissions managed | Covered |

### P-74: Proof of Reserves
Detects balance reconciliation, overdraft prevention, double-entry patterns.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-75: Audit Immutability
Detects audit triggers, append-only enforcement, actor attribution, retention.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.3.1 — Limit audit log access; 10.3.2 — Protect log integrity | Covered |
| SOC 2 | CC4.1 — Monitoring; CC7.2 — Anomalies | Covered |
| ISO 27001 | A.8.15 — Logging | Covered |
| NIST CSF | PR.PT-1 — Audit logs maintained | Covered |
| CIS v8 | 8.5 — Collect detailed audit logs | Covered |

### P-76: Payment State Machine
Detects valid state transitions, terminal states, expiration policies.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-77: Withdrawal Controls
Detects withdrawal limits, address whitelist, cooldown, 2FA on withdrawals.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.4.2 — MFA enforcement | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.5.16 — Identity management | Covered |
| NIST CSF | PR.AA-3 — Authentication | Covered |
| CIS v8 | 6.3 — Require MFA | Covered |

### P-78: Ledger Consistency
Detects atomic balance updates, drift detection, orphans, idempotent updates.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-79: Regulatory Reporting
Detects CTR readiness, SAR mechanisms, regulatory export capabilities.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC2.3 — Compliance obligations | Covered |
| ISO 27001 | A.5.31 — Legal requirements | Covered |
| NIST CSF | ID.GV-3 — Legal and regulatory requirements | Covered |

### P-80: Financial Event Sourcing
Detects event log immutability, history tables, point-in-time queries, lineage.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 10.2 — Audit log implementation | Covered |
| SOC 2 | CC4.1 — Monitoring | Covered |
| ISO 27001 | A.8.15 — Logging | Covered |
| NIST CSF | PR.PT-1 — Audit logs maintained | Covered |

### P-81: Financial Input Guards
Detects negative amounts, integer overflow, NaN/Infinity, type coercion, precision.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding; 6.5.1 — Injection flaws | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| OWASP API | API3:2023 — Broken Object Property Level Authorization | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |
| CIS v8 | 16.10 — Apply secure design principles | Covered |

### P-82: Continuous Defense Model
Detects real-time monitoring, auto-response, audit automation, circuit breakers.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC7.3 — Security incidents | Covered |
| ISO 27001 | A.5.24 — Incident response | Covered |
| NIST CSF | DE.CM-1 — Network monitoring; RS.AN-1 — Notification process | Covered |
| CIS v8 | 17.1 — Designate incident response personnel | Covered |

### P-83: Physical Access Evidence
Verifies physical security docs, badge system references, data center documentation.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 9.1 — Physical access controls; 9.2 — Visitor management | Covered |
| SOC 2 | CC6.4 — Physical access | Covered |
| ISO 27001 | A.7.1 — Physical security perimeters | Covered |
| NIST CSF | PR.AC-2 — Physical access managed | Covered |
| CIS v8 | 13.10 — Perform application layer filtering | Covered |

### P-84: Organizational Policies
Verifies security policy, acceptable use, risk assessment, training, vendor mgmt.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 12.1 — Establish security policy; 12.6 — Security awareness | Covered |
| SOC 2 | CC1.1 — Demonstrates commitment to integrity | Covered |
| ISO 27001 | A.5.1 — Policies for information security | Covered |
| NIST CSF | GV.PO-1 — Policy established | Covered |
| CIS v8 | 14.1 — Establish security awareness program | Covered |

### P-85: SOC 2 Availability
Verifies capacity planning, SLA documentation, infrastructure redundancy.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | A1.1 — Capacity; A1.2 — Environmental; A1.3 — Recovery | Covered |
| ISO 27001 | A.8.6 — Capacity management | Covered |
| NIST CSF | RC.RP-1 — Recovery plan executed | Covered |

### P-86: SOC 2 Confidentiality
Verifies data classification, NDA references, DLP controls.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | C1.1 — Confidentiality identification; C1.2 — Confidentiality maintenance | Covered |
| ISO 27001 | A.5.12 — Classification of information | Covered |
| NIST CSF | PR.DS-5 — Data leak protections | Covered |

### P-87: ISO Organizational Controls
Verifies ISMS scope, threat intelligence, supplier mgmt, cloud security, incident mgmt.

| Framework | Requirement | Status |
|---|---|---|
| ISO 27001 | A.5.1..A.5.37 — Organizational controls | Covered |
| SOC 2 | CC1.x — Organizational governance | Covered |

### P-88: ISO People Controls
Verifies screening, security training, offboarding, remote work policy.

| Framework | Requirement | Status |
|---|---|---|
| ISO 27001 | A.6.1..A.6.8 — People controls | Covered |
| SOC 2 | CC1.4 — Workforce competence | Covered |

### P-89: ISO Physical Controls
Verifies data center docs, equipment security, environmental monitoring.

| Framework | Requirement | Status |
|---|---|---|
| ISO 27001 | A.7.1..A.7.14 — Physical controls | Covered |
| PCI-DSS v4.0 | 9.x — Physical security | Covered |

### P-90: NIST Govern
Verifies organizational context, risk strategy, roles, supply chain governance.

| Framework | Requirement | Status |
|---|---|---|
| NIST CSF | GV.OC; GV.RM; GV.RR; GV.PO; GV.SC | Covered |
| ISO 27001 | A.5.1..A.5.4 — Organizational policies | Covered |

### P-91: NIST Identify
Verifies asset inventory, risk assessment, improvement tracking.

| Framework | Requirement | Status |
|---|---|---|
| NIST CSF | ID.AM; ID.RA; ID.IM | Covered |
| CIS v8 | 1.1 — Establish enterprise asset inventory | Covered |

### P-92: NIST Recover
Verifies recovery planning, recovery communications.

| Framework | Requirement | Status |
|---|---|---|
| NIST CSF | RC.RP; RC.CO | Covered |
| ISO 27001 | A.5.30 — ICT readiness for business continuity | Covered |

### P-93: CIS Asset Inventory
Verifies service catalog, infrastructure-as-code, monitoring tools.

| Framework | Requirement | Status |
|---|---|---|
| CIS v8 | 1.1; 1.2; 2.1 — Inventory controls | Covered |
| NIST CSF | ID.AM-1; ID.AM-2 — Asset management | Covered |

### P-94: CIS Security Training
Verifies training docs, platform references, secure coding standards.

| Framework | Requirement | Status |
|---|---|---|
| CIS v8 | 14.1; 14.6 — Security awareness | Covered |
| ISO 27001 | A.6.3 — Information security awareness | Covered |
| SOC 2 | CC2.2 — Internal communication | Covered |

### P-95: CIS Service Provider and Pentest
Verifies vendor assessments, pentest program, vulnerability scan schedule.

| Framework | Requirement | Status |
|---|---|---|
| CIS v8 | 15.1; 18.1 — Service providers; pentest program | Covered |
| ISO 27001 | A.5.19 — Information security in supplier relationships | Covered |
| NIST CSF | GV.SC; ID.RA-1 — Supply chain; vulnerability assessments | Covered |

### P-96: Integer Overflow Detection
Detects unchecked arithmetic on financial values across multiple languages.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-97: Division Precision
Detects unsafe division patterns that lose precision in financial computations.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-98: Currency Safety
Detects mixed-currency arithmetic and missing currency tagging on amounts.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-99: Boundary Values
Detects missing zero, max-value, and edge-case handling on financial inputs.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-100: Mathematical Invariants
Detects violations of conservation invariants in financial calculations.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-101: Money Type Precision
Detects float/double for money in Java, Python, Go, Rust, TypeScript, JavaScript.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-102: Financial Math Accuracy
Detects division without scale, premature truncation, unsafe rounding modes.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.28 — Secure coding | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |

### P-103: Double-Spend Race Conditions
Detects missing locking on financial mutations, concurrent withdrawal patterns.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.2.4 — Secure coding; 6.5.1 — Injection flaws | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.25 — Secure development lifecycle | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |
| CIS v8 | 16.10 — Apply secure design principles | Covered |

### P-200: PII Protection
Detects PII in logs, URLs, error messages, and client-bound JSON.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 3.4 — Render PAN unreadable; 8.3.2 — Strong passwords | Covered |
| SOC 2 | P1.1 — Privacy notice; P5.1 — Personal information | Covered |
| ISO 27001 | A.8.11 — Data masking; A.8.12 — Data leakage prevention | Covered |
| NIST CSF | PR.DS-1 — Data protection | Covered |
| CIS v8 | 3.13 — Deploy data loss prevention | Covered |

### P-210: Compliance Controls
Verifies presence of compliance configuration documentation and controls.

| Framework | Requirement | Status |
|---|---|---|
| SOC 2 | CC1.1 — Integrity and ethics | Covered |
| ISO 27001 | A.5.1 — Policies for information security | Covered |
| NIST CSF | GV.PO-1 — Policy established | Covered |

### P-220: Data Integrity
Detects missing constraints, integrity violations, and data drift indicators.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 11.5.2 — File integrity monitoring | Covered |
| SOC 2 | CC8.1 — Processing integrity | Covered |
| ISO 27001 | A.8.7 — Protection against malware | Covered |
| NIST CSF | PR.DS-6 — Integrity checking | Covered |
| CIS v8 | 3.6 — Encrypt data on end-user devices | Covered |

### P-230: Infrastructure Security
Detects infrastructure misconfigurations, missing hardening, exposed services.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 1.2 — Configure firewalls; 2.2 — Configuration standards | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.9 — Configuration management | Covered |
| NIST CSF | PR.IP-1 — Baseline configuration | Covered |
| CIS v8 | 4.1 — Establish secure configuration process | Covered |

### P-240: API Security
Detects API security misconfigurations, missing rate limits, weak auth.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.4.1 — Public-facing web apps | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.26 — Application security requirements | Covered |
| OWASP API | API1; API2; API3; API4; API8 | Covered |
| NIST CSF | PR.AC-3 — Remote access managed | Covered |

### P-250: Webhook Security
Detects missing signature verification, replay protection on webhooks.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.4.1 — Public-facing web apps | Covered |
| SOC 2 | CC6.6 — System boundaries | Covered |
| ISO 27001 | A.8.26 — Application security requirements | Covered |
| NIST CSF | PR.DS-2 — Data-in-transit protected | Covered |

### P-260: Crypto Standards
Verifies use of approved algorithms, key sizes, and modes.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 4.2.1 — Strong cryptography in transmission; 3.6 — Cryptographic key management | Covered |
| SOC 2 | CC6.7 — Restrict data transmission | Covered |
| ISO 27001 | A.8.24 — Use of cryptography | Covered |
| NIST CSF | PR.DS-2 — Data-in-transit protected | Covered |
| CIS v8 | 3.10 — Encrypt sensitive data in transit | Covered |

### P-270: Session Security
Detects missing session controls, weak session token generation, insecure cookies.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 8.2 — Identify users; 8.6 — Token security | Covered |
| SOC 2 | CC6.1 — Logical access | Covered |
| ISO 27001 | A.8.5 — Secure authentication | Covered |
| OWASP API | API2:2023 — Broken Authentication | Covered |
| NIST CSF | PR.AC-7 — User authentication | Covered |
| CIS v8 | 6.5 — Session management | Covered |

### P-280: Supply Chain
Detects supply chain risks, missing dependency pinning, unsigned artifacts.

| Framework | Requirement | Status |
|---|---|---|
| PCI-DSS v4.0 | 6.3.2 — Inventory of third-party components | Covered |
| SOC 2 | CC9.2 — Vendor management | Covered |
| ISO 27001 | A.5.19 — Supplier relationships; A.8.28 — Secure coding | Covered |
| OWASP API | API10:2023 — Unsafe Consumption of APIs | Covered |
| NIST CSF | GV.SC — Cybersecurity supply chain risk management | Covered |
| CIS v8 | 16.4 — Audit third-party software | Covered |
