# Open Items

Durable request queue. One row per incoming request, in the order received.
An item leaves this file only by being completed and deployed, or by Diego
explicitly dropping it. Blocked items move to the Blocked section and MUST name
the exact condition that would unblock them.

| # | Received | Request | Status |
|---|----------|---------|--------|
| 1 | 2026-09-06 | Failure alerts arriving for the last few days — find the failing workflow(s), diagnose the actual cause from run logs, fix, and verify. | DONE 2026-09-06 — three defects found; two fixed and verified at runtime, one merged and awaiting its first live cycle (see Blocked #2). Release run 34064649300 green end-to-end; tap formula carries 4 bottles again. |

## Blocked

| # | Item | Unblocks when |
|---|------|---------------|
| 2 | Promotion-PR race fix (PR #861, master `c53decbc`) is merged but has not yet run. | The next threat-intel orchestrate cycle that has candidates opens a promotion PR. Its `Tests`, `Lint community checks` and `Security Audit` runs must complete green rather than dying with `jobs: []`. Cycles at 20:37 and 22:34 on 2026-09-06 ran green but had nothing to promote. |
| 3 | Watchdog alert e-mails continue for up to one more cycle. | The two pre-fix Release failures (runs 34000628028, 34012753556) age out of the watchdog's 25-hour lookback, expected after ~2026-09-07 05:00 UTC. Self-resolving; no action needed unless alerts persist past 06:00 UTC. |
