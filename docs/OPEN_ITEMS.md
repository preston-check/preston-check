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
| 2 | **REGRESSION — promotion stalled 2026-09-06 → 2026-09-08.** PR #861's "wait for promotion PR checks" was built on a wrong diagnosis. Runs on a PR opened by `github-actions[bot]` are created `action_required` and never start, so the wait polled a verdict that could never arrive, timed out, and skipped the merge. PRs #879–#882 open, no new checks reaching master for two days. Correct fix pushed: master `d6ed898d` approves the pending runs first (workflow already holds `actions: write`). | (a) the next orchestrate cycle **with candidates** shows `Approve the promotion PR's pending checks` → checks green → merge; and (b) the #879–#882 backlog is drained. Draining needs an approve-then-merge loop per PR — the sandbox classifier blocks that mutating loop, so it needs Diego's go-ahead or a permission rule. |
| 3 | ~~Watchdog alerts from the pre-fix Release failures~~ — **original cause RESOLVED**; runs 34000628028/34012753556 have aged out of the 25h lookback. | Nothing outstanding of its own. The watchdog is still red, but now for one correct reason: it is reporting item #2 (`1 promotion PR(s) open for >24h ... e.g. #879`). It caught the regression. Alerts stop when #2 is drained. |

## Coverage gaps — CLOSED 2026-09-08

Diego asked for all four; all four are closed and verified in CI
(run 34232259442: **170 passed, 0 failed, 74 surfaces**).
Current scope and its deliberate limits: `docs/quality-gate-coverage.md`.

| Gap | Closed by |
|-----|-----------|
| Licence generation never executed | Throwaway Ed25519 key per run; the issued licence is verified by `lib/license.sh` — the CLI's own openssl verifier — and a tampered payload must be rejected |
| Front-end interaction never driven | `suites/flow.mjs` drives the sign-in funnel in a browser against real Workers: login screen → e-mail → code step → verify → signed-in → token persisted |
| SES SigV4 never run | `lib/ses.mjs` independently re-derives the signature from the received request; the request is still signed for the real SES host |
| CLI / lib/ / checks outside the gate | `suites/cli.mjs`: run-tests.sh, metadata evidence, corpus size + bash validity, fixture scans, airgapped self-scan, `--framework` |
| `action.yml`, `install.sh`, `docker/`, `ai-addon/` | `suites/packaging.mjs`, including a non-root `USER` assertion on the image |

## Notes for the next session

The quality gate needs **Node >= 22**; this repo's other workflows pin Node 20,
and `.github/workflows/quality-gate.yml` deliberately pins 24. Locally the gate
needs `nvm install 24` — Diego's current Node is 20.20.2, which can run the
front-end and invariant suites but not the Worker suites.
