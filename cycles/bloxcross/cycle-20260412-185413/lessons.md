# Virtuous Cycle Lessons — Cycle 20260412-185413

## Loop 1: New Things Learned From Data & Executions

What did this cycle reveal that we didn't know before? These are insights
from the check results, delta analysis, and log patterns that should inform
future development practices.

### Observations
- FINDING:[0m P-05 Webhook idempotency                 6 of 10 webhook handlers lack idempotency
- FINDING:[0m P-08 Command injection                          5 potential command execution sites
- OBSERVATION:[0m P-02 2FA bypass paths                          10 potential 2FA bypass paths (review manually)
- OBSERVATION:[0m P-03 Exception leakage                         10 potential exception message leaks in responses
- OBSERVATION:[0m P-03 Sensitive field exposure                  10 sensitive fields may be serialized (check @JsonIgnore)
- OBSERVATION:[0m P-04 Rate limiting                       80 of 101 controllers lack rate limiting
- OBSERVATION:[0m P-05 Financial locking                   Only 7 of 20 financial files use locking
- OBSERVATION:[0m P-06 Session IP binding                  No evidence of login IP stored in session
- OBSERVATION:[0m P-08 SQL injection                             10 potential SQL concatenation sites (verify parameterized)
- OBSERVATION:[0m P-10 Rapid polling (current)             Peak: 40 requests/minute in Client.log
- OBSERVATION:[0m P-10 Blacklist activity                  Recent blacklist events detected in logs
- OBSERVATION:[0m P-11 No plaintext HTTP                          1 non-localhost HTTP URLs found (should be HTTPS)

### For Claude: Analyze the FAIL and WARN results above. For each one,
write a 1-2 sentence insight about what this tells us about the codebase
or development process that produced this result. What pattern or practice
led to this issue?

---

## Loop 2: New Potential Threats Detected

What new attack vectors, vulnerabilities, or risk patterns emerged in this cycle
that were not present in previous cycles? These should be added to the detection
rules and monitoring.

### New vs Previous
No new threats — all current issues existed in the previous cycle.

### For Claude: Review any NEW threats above. For each one, propose a new
Preston-Check rule or enhancement to an existing rule that would detect
this threat earlier in future cycles.

---

## Loop 3: What Worked Well — Expand and Implement Broadly

What security practices are working and should be replicated across the
entire codebase or to other modules?

### Strong Areas (consistent PASS)
- STRONG:[0m P-01 Hardcoded secrets                   No hardcoded secrets found in source
- STRONG:[0m P-02 2FA default state                   No default-to-NONE 2FA patterns
- STRONG:[0m P-06 Session expiration                  Sessions have TTL configured
- STRONG:[0m P-06 Session kill capability             Session termination available for remediation
- STRONG:[0m P-07 Blacklist in registration           Blacklist check found in registration/KYC flow
- STRONG:[0m P-07 Blacklist on name change            Name changes check against blacklist
- STRONG:[0m P-09 DB audit triggers                         10 audit trigger definitions found
- STRONG:[0m P-09 Append-only ledger                  Delete prevention on financial tables found
- STRONG:[0m P-10 Brute force (current)               No brute force activity in current logs
- STRONG:[0m P-10 Withdraw 2FA failures               No recent 2FA failures on withdrawals
- STRONG:[0m P-12 Balance validation                         5 balance check patterns in financial paths
- STRONG:[0m P-12 Negative amount check               Amount validation found
- STRONG:[0m P-12 Row locking                               10 row-locking patterns for financial operations
- STRONG:[0m P-12 Transaction IDs                     Collision-resistant transaction ID generation found
- STRONG:[0m P-13 JWT verification                    JWT signature verification found

### For Claude: Identify which PASS results represent practices that are
NOT yet applied universally. For example, if blacklist checks pass in
registration but are not present in other user-creation flows, recommend
expanding them. Propose specific locations where strong practices should
be replicated.

---

## Summary

| Loop | Count |
|------|-------|
| New learnings | 21 findings to analyze |
| New threats | 0 new issues |
| Strong practices | 28 areas working well |
