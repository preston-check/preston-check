#!/usr/bin/env node
/**
 * quality-gate-test — the pre-deployment acceptance gate.
 *
 * Boots every Worker under the real workerd runtime with real local D1/KV,
 * exercises every route and every Stripe webhook event type, renders every
 * front-end page, checks deployment invariants, and then verifies that the
 * set of surface ids actually asserted equals the inventory in surface.json.
 *
 * Exit 0 only if all three hold:
 *   1. every assertion passed
 *   2. every id in surface.json was asserted by some suite
 *   3. the surface inventory still matches what the sources actually expose
 *
 * (2) and (3) are what stop this decaying into a snapshot: a new route or a
 * new webhook event fails the gate until it is both inventoried and tested.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Results, banner, warn, info } from './lib/harness.mjs';
import { Worker } from './lib/worker.mjs';
import { startStripeMock, WEBHOOK_SECRET } from './lib/stripe.mjs';
import { checkDrift } from './drift-check.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const SURFACE = JSON.parse(readFileSync(join(HERE, 'surface.json'), 'utf8'));

const argv = process.argv.slice(2);
const only = argv.includes('--only') ? argv[argv.indexOf('--only') + 1] : null;
const wants = (name) => !only || only.split(',').includes(name);

const STRIPE_MOCK_PORT = 8899;

/** Every id the inventory says must be covered. */
function expectedIds() {
  const ids = [];
  for (const w of Object.values(SURFACE.workers)) {
    for (const r of w.routes) ids.push(r.id);
    for (const e of (w.webhook_events || [])) ids.push(e.id);
  }
  for (const f of SURFACE.frontends) ids.push(f.id);
  for (const i of SURFACE.invariants) ids.push(i.id);
  return ids;
}

async function main() {
  banner('  PRESTON-CHECK QUALITY GATE\n  Every endpoint · every webhook · every rendered page');

  const results = new Results();
  const started = [];
  let stripeMock = null;

  try {
    // ---------- Workers ----------
    if (wants('auth')) {
      const w = new Worker(ROOT, SURFACE.workers.auth, 'auth');
      w.seed(); await w.start({ SESSION_SECRET: 'qg-session-secret' });
      started.push(w);
      const { run } = await import('./suites/auth.mjs');
      await run(results, w);
    }

    if (wants('billing') || wants('webhook')) {
      stripeMock = await startStripeMock(STRIPE_MOCK_PORT);
      info(`stripe mock listening on ${stripeMock.base}`);
      const w = new Worker(ROOT, SURFACE.workers.billing, 'billing');
      w.seed();
      await w.start({
        STRIPE_API_BASE: stripeMock.base,
        STRIPE_SECRET_KEY: 'sk_test_quality_gate',
        STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET,
        STRIPE_PRICE_PRO_PER_REPO: 'price_qg_per_repo',
        STRIPE_PRICE_PRO_UNLIMITED: 'price_qg_unlimited',
      });
      started.push(w);
      if (wants('billing')) {
        const { run } = await import('./suites/billing.mjs');
        await run(results, w);
      }
      if (wants('webhook')) {
        const { run } = await import('./suites/webhook.mjs');
        await run(results, w, SURFACE.workers.billing.webhook_events);
      }
    }

    if (wants('telemetry')) {
      const w = new Worker(ROOT, SURFACE.workers.telemetry, 'telemetry');
      w.seed(); await w.start();
      started.push(w);
      const { run } = await import('./suites/telemetry.mjs');
      await run(results, w);
    }

    if (wants('get')) {
      const w = new Worker(ROOT, SURFACE.workers.get, 'get');
      w.seed(); await w.start();
      started.push(w);
      const { run } = await import('./suites/get.mjs');
      await run(results, w);
    }

    // ---------- Front ends ----------
    if (wants('frontend')) {
      const { run } = await import('./suites/frontend.mjs');
      await run(results, ROOT, SURFACE.frontends, SURFACE.frontend_apps);
    }

    // ---------- Deployment invariants ----------
    if (wants('invariants')) {
      const { run } = await import('./suites/invariants.mjs');
      await run(results, ROOT);
    }
  } catch (err) {
    results.suite('Harness');
    results.record('harness', 'gate ran to completion', false, err.stack || String(err));
  } finally {
    for (const w of started) w.stop();
    if (stripeMock) await stripeMock.close();
  }

  // ---------- Coverage reconciliation ----------
  let coverageOk = true;
  if (!only) {
    results.suite('Coverage reconciliation');
    const expected = expectedIds();
    const missing = expected.filter(id => !results.covered.has(id));
    const stale = [...results.covered].filter(id => !expected.includes(id) && id !== 'harness');

    results.record('coverage.complete',
      `all ${expected.length} inventoried surfaces asserted`,
      missing.length === 0,
      missing.length ? `never asserted: ${missing.join(', ')}` : null);
    results.record('coverage.no-stale',
      'no assertions against surfaces absent from the inventory',
      stale.length === 0,
      stale.length ? `not in surface.json: ${stale.join(', ')}` : null);

    const drift = checkDrift(ROOT, SURFACE);
    results.record('coverage.no-drift',
      'inventory matches what the sources actually expose',
      drift.ok, drift.problems.join('; ') || null);

    coverageOk = missing.length === 0 && stale.length === 0 && drift.ok;
  } else {
    warn(`--only ${only}: coverage reconciliation skipped, this run CANNOT gate a deploy`);
  }

  // ---------- Verdict ----------
  const pass = results.passed.length, fail = results.failed.length;
  banner(`  RESULT: ${pass} passed, ${fail} failed`);
  if (fail) {
    for (const f of results.failed) {
      process.stdout.write(`  ✗ [${f.suite}] ${f.id} — ${f.description}\n`);
      if (f.detail) process.stdout.write(`      ${f.detail}\n`);
    }
  }

  const green = results.ok && coverageOk;
  process.stdout.write(green
    ? '\n  QUALITY GATE PASSED — safe to deploy\n\n'
    : '\n  QUALITY GATE FAILED — deployment must not proceed\n\n');
  process.exit(green ? 0 : 1);
}

main();
