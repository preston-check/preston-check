# Open Items

Durable request queue. One row per incoming request, in the order received.
An item leaves this file only by being completed and deployed, or by Diego
explicitly dropping it. Blocked items move to the Blocked section and MUST name
the exact condition that would unblock them.

| # | Received | Request | Status |
|---|----------|---------|--------|
| 1 | 2026-09-06 | Failure alerts arriving for the last few days — find the failing workflow(s), diagnose the actual cause from run logs, fix, and verify. | DONE 2026-09-06 — three defects found; two fixed and verified at runtime, one merged awaiting its first live cycle (Blocked #2). Release run 34064649300 green; tap formula carries 4 bottles again. |
| 4 | 2026-09-06 | Build `quality-gate-test`: comprehensive acceptance test covering 100% of endpoints, webhooks, functionality and rendered front ends. Runnable ahead of every deployment; no deployment to production without it. | DONE 2026-09-06 — PR #878, master `3be6da49`. 117 assertions over 58 inventoried surfaces, 0 failures (run 34066269285). Enforcement proven live: pages.yml run 34066383807 shows `quality-gate → build → deploy`. |

## Blocked

| # | Item | Unblocks when |
|---|------|---------------|
| 2 | Promotion-PR race fix (PR #861, master `c53decbc`) is merged but has not yet run. | The next threat-intel orchestrate cycle that has candidates opens a promotion PR. Its `Tests`, `Lint community checks` and `Security Audit` runs must complete green rather than dying with `jobs: []`. |
| 3 | Watchdog alert e-mails continue for up to one more cycle. | The two pre-fix Release failures (runs 34000628028, 34012753556) age out of the 25-hour lookback, expected after ~2026-09-07 05:00 UTC. Self-resolving; act only if alerts persist past 06:00 UTC. |

## Notes for the next session

The quality gate needs **Node >= 22**; this repo's other workflows pin Node 20,
and `.github/workflows/quality-gate.yml` deliberately pins 24. Locally the gate
needs `nvm install 24` — Diego's current Node is 20.20.2, which can run the
front-end and invariant suites but not the Worker suites.
