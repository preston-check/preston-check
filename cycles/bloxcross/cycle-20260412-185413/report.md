# Preston-Check Security Audit Report

Date: 2026-04-12 18:55:30
App: bloxcross
Source: /Users/diegofbaez/DEV/bloxcross_master_stable/bloxcross

## Results

| Status | Check | Detail |
|--------|-------|--------|
| PASS | P-01 Hardcoded secrets | No hardcoded secrets found in source |
| WARN | P-02 2FA bypass paths |       10 potential 2FA bypass paths (review manually) |
| PASS | P-02 2FA default state | No default-to-NONE 2FA patterns |
| WARN | P-03 Exception leakage |       10 potential exception message leaks in responses |
| WARN | P-03 Sensitive field exposure |       10 sensitive fields may be serialized (check @JsonIgnore) |
| WARN | P-04 Rate limiting | 80 of 101 controllers lack rate limiting |
| FAIL | P-05 Webhook idempotency | 6 of 10 webhook handlers lack idempotency |
| WARN | P-05 Financial locking | Only 7 of 20 financial files use locking |
| WARN | P-06 Session IP binding | No evidence of login IP stored in session |
| PASS | P-06 Session expiration | Sessions have TTL configured |
| PASS | P-06 Session kill capability | Session termination available for remediation |
| PASS | P-07 Blacklist in registration | Blacklist check found in registration/KYC flow |
| PASS | P-07 Blacklist on name change | Name changes check against blacklist |
| WARN | P-08 SQL injection |       10 potential SQL concatenation sites (verify parameterized) |
| FAIL | P-08 Command injection |        5 potential command execution sites |
| PASS | P-09 DB audit triggers |       10 audit trigger definitions found |
| PASS | P-09 Append-only ledger | Delete prevention on financial tables found |
| PASS | P-10 Brute force (current) | No brute force activity in current logs |
| WARN | P-10 Rapid polling (current) | Peak: 40 requests/minute in Client.log |
| WARN | P-10 Blacklist activity | Recent blacklist events detected in logs |
| PASS | P-10 Withdraw 2FA failures | No recent 2FA failures on withdrawals |
| WARN | P-11 No plaintext HTTP |        1 non-localhost HTTP URLs found (should be HTTPS) |
| WARN | P-11 No weak crypto |        1 weak encryption patterns (DES/RC4/MD5/ECB) |
| WARN | P-11 SSL enabled | No SSL configuration found |
| PASS | P-12 Balance validation |        5 balance check patterns in financial paths |
| PASS | P-12 Negative amount check | Amount validation found |
| PASS | P-12 Row locking |       10 row-locking patterns for financial operations |
| PASS | P-12 Transaction IDs | Collision-resistant transaction ID generation found |
| WARN | P-13 Auth on controllers |        2 controllers may lack auth enforcement |
| WARN | P-13 Anonymous endpoints |       10 publicly accessible endpoints (review intentionality) |
| PASS | P-13 JWT verification | JWT signature verification found |
| PASS | P-14 Bouncy Castle version | No deprecated bcpkix-jdk15on found |
| PASS | P-14 No SNAPSHOT deps | No SNAPSHOT dependencies in production |
| SKIP | P-14 npm audit | No package.json found |
| PASS | P-15 No wildcard CORS | No Access-Control-Allow-Origin: * found |
| WARN | P-15 CSRF protection | No CSRF protection patterns found |
| WARN | P-16 No printStackTrace |      880 e.printStackTrace() calls (should use logger) |
| PASS | P-16 No swallowed exceptions | No empty catch blocks found |
| WARN | P-16 Generic error messages | Check that error responses don't leak stack traces |
| PASS | P-17 Secure randomness | No java.util.Random or Math.random() found |
| PASS | P-17 SecureRandom present | SecureRandom used in Common module |
| PASS | P-18 Password hashing | Password hashing mechanism found |
| WARN | P-18 PII in logs |       82 potential PII fields in log statements (consider masking) |
| PASS | P-18 Password serialization |       40 password fields have @JsonIgnore |
| PASS | P-19 API versioning |       10 versioned API paths found |
| WARN | P-19 No deprecated endpoints |        4 deprecated endpoints still active |
| PASS | P-20 No debug mode | No debug/dev mode enabled in configs |
| PASS | P-20 No test credentials | No test/default credentials in configs |
| PASS | P-20 Health endpoint | Health check endpoint found |
| PASS | P-20 DB migrations |       20 migration files (structured deployment) |

## Summary

PASS: 28, FAIL: 2, WARN: 19, SKIP: 1
