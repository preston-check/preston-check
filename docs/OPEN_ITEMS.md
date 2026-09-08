# Open Items

Durable request queue. One row per incoming request, in the order received.
An item leaves this file only by being completed and deployed, or by Diego
explicitly dropping it. Blocked items move to the Blocked section and MUST name
the exact condition that would unblock them.

| # | Received | Request | Status |
|---|----------|---------|--------|
| 1 | 2026-09-06 | Failure alerts arriving for the last few days — find the failing workflow(s), diagnose the actual cause from run logs, fix, and verify. | DONE 2026-09-06 — three defects found; two fixed and verified at runtime, one merged awaiting its first live cycle (Blocked #2). Release run 34064649300 green; tap formula carries 4 bottles again. |
| 4 | 2026-09-06 | Build `quality-gate-test`: comprehensive acceptance test covering 100% of endpoints, webhooks, functionality and rendered front ends. Runnable ahead of every deployment; no deployment to production without it. | DONE 2026-09-06 — PR #878, master `3be6da49`. 117 assertions over 58 inventoried surfaces, 0 failures (run 34066269285). Enforcement proven live: pages.yml run 34066383807 shows `quality-gate → build → deploy`. |

| 5 | 2026-09-08 | "Are we at 100% coverage?" — audit the gate's real coverage against the product. | ANSWERED 2026-09-08 — no. 100% of a 59-surface inventory, but that inventory excludes licence generation, front-end interaction, SES/Resend delivery, the CLI/lib/checks, action.yml, install.sh, docker/ and ai-addon/. Written up in `docs/quality-gate-coverage.md`. Structural hole closed same day: `release.yml` now depends on `test.yml` (`inv.release-gated-on-cli-tests`). Remaining gaps OPEN below. |

## Blocked

| # | Item | Unblocks when |
|---|------|---------------|
| 2 | Promotion-PR race fix (PR #861, master `c53decbc`) is merged but has not yet run. | The next threat-intel orchestrate cycle that has candidates opens a promotion PR. Its `Tests`, `Lint community checks` and `Security Audit` runs must complete green rather than dying with `jobs: []`. |
| 3 | Watchdog alert e-mails continue for up to one more cycle. | The two pre-fix Release failures (runs 34000628028, 34012753556) age out of the 25-hour lookback, expected after ~2026-09-07 05:00 UTC. Self-resolving; act only if alerts persist past 06:00 UTC. |

## Open coverage gaps (from the 2026-09-08 audit)

Diego 2026-09-08: close **all four**. Detail and rationale in `docs/quality-gate-coverage.md`.

| Gap | Why it matters |
|-----|----------------|
| Licence generation (`generateLicenseFile`, Ed25519) never executes — `LICENSE_SIGNING_KEY` unset in gate runs | The file a paying customer receives on completing checkout is untested |
| Front-end interaction — 534 lines of app.js never driven (sign-in flow, checkout, licence download) | Only initial render is asserted; the customer funnel itself is unverified |
| SES SigV4 + Resend delivery paths never run | Hand-rolled SigV4 signing is entirely untested |
| CLI / lib/ / 1146 checks not in the gate | Covered by the `Tests` workflow, now a release dependency, but outside the gate |
| `action.yml`, `install.sh`, `docker/`, `ai-addon/` (38 files) | No coverage at all |

## Notes for the next session

The quality gate needs **Node >= 22**; this repo's other workflows pin Node 20,
and `.github/workflows/quality-gate.yml` deliberately pins 24. Locally the gate
needs `nvm install 24` — Diego's current Node is 20.20.2, which can run the
front-end and invariant suites but not the Worker suites.
