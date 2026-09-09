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
import { makeLicenceKeypair } from './lib/licence.mjs';
import { startSesMock, SES_KEY_ID, SES_SECRET, SES_REGION } from './lib/ses.mjs';
import { checkDrift } from './drift-check.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const SURFACE = JSON.parse(readFileSync(join(HERE, 'surface.json'), 'utf8'));

const argv = process.argv.slice(2);
const only = argv.includes('--only') ? argv[argv.indexOf('--only') + 1] : null;
const wants = (name) => !only || only.split(',').includes(name);

const STRIPE_MOCK_PORT = 8899;
const SES_MOCK_PORT = 8898;

/** Every id the inventory says must be covered. */
function expectedIds() {
  const ids = [];
  for (const w of Object.values(SURFACE.workers)) {
    for (const r of w.routes) ids.push(r.id);
    for (const e of (w.webhook_events || [])) ids.push(e.id);
  }
  for (const f of SURFACE.frontends) ids.push(f.id);
  for (const i of SURFACE.invariants) ids.push(i.id);
  for (const a of (SURFACE.artefacts || [])) ids.push(a.id);
  return ids;
}

async function main() {
  banner('  PRESTON-CHECK QUALITY GATE\n  Every endpoint · every webhook · every rendered page');

  const results = new Results();
  const started = [];
  let stripeMock = null;
  let sesMock = null;

  try {
    // ---------- Workers ----------
    if (wants('auth')) {
      const w = new Worker(ROOT, SURFACE.workers.auth, 'auth');
      w.seed(); await w.start({ SESSION_SECRET: 'qg-session-secret' });
      started.push(w);
      const { run } = await import('./suites/auth.mjs');
      await run(results, w);
    }

    if (wants('billing') || wants('webhook') || wants('licence')) {
      stripeMock = await startStripeMock(STRIPE_MOCK_PORT);
      info(`stripe mock listening on ${stripeMock.base}`);
      // Throwaway signing pair per run: the real key is a Worker secret, and
      // without one set the licence path could never execute at all.
      const licenceKeys = makeLicenceKeypair();
      const w = new Worker(ROOT, SURFACE.workers.billing, 'billing');
      w.seed();
      await w.start({
        STRIPE_API_BASE: stripeMock.base,
        STRIPE_SECRET_KEY: 'sk_test_quality_gate',
        STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET,
        STRIPE_PRICE_PRO_PER_REPO: 'price_qg_per_repo',
        STRIPE_PRICE_PRO_UNLIMITED: 'price_qg_unlimited',
        LICENSE_SIGNING_KEY: licenceKeys.pkcs8B64,
      });
      started.push(w);
      if (wants('licence')) {
        const { run } = await import('./suites/licence.mjs');
        await run(results, w, ROOT, licenceKeys.publicPem);
      }
      if (wants('billing')) {
        const { run } = await import('./suites/billing.mjs');
        await run(results, w);
      }
      if (wants('webhook')) {
        const { run } = await import('./suites/webhook.mjs');
        await run(results, w, SURFACE.workers.billing.webhook_events);
      }
    }

    // A second auth instance, this one with SES credentials. Kept separate so
    // the primary auth suite still exercises the no-credentials fallback,
    // which is what a misconfigured deploy actually hits.
    if (wants('email')) {
      sesMock = await startSesMock(SES_MOCK_PORT);
      info(`ses mock listening on ${sesMock.base}`);
      const spec = { ...SURFACE.workers.auth, port: SURFACE.workers.auth.port + 40 };
      const w = new Worker(ROOT, spec, 'auth-ses');
      w.seed();
      await w.start({
        SESSION_SECRET: 'qg-session-secret',
        SES_API_BASE: sesMock.base,
        SES_AWS_ACCESS_KEY_ID: SES_KEY_ID,
        SES_AWS_SECRET_ACCESS_KEY: SES_SECRET,
        SES_AWS_REGION: SES_REGION,
      });
      started.push(w);
      const { run } = await import('./suites/email.mjs');
      await run(results, w, sesMock);
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

    // ---------- Customer journey, browser to real Workers ----------
    // Dedicated instances: the page origin must be in ALLOW_ORIGIN for the
    // browser's cross-origin calls to be permitted, and the shared instances
    // deliberately keep the production origin so CORS is asserted as deployed.
    if (wants('flow')) {
      const { FLOW_PAGE_ORIGIN, run } = await import('./suites/flow.mjs');
      if (!stripeMock) stripeMock = await startStripeMock(STRIPE_MOCK_PORT);

      const authSpec = { ...SURFACE.workers.auth, port: SURFACE.workers.auth.port + 60 };
      const aw = new Worker(ROOT, authSpec, 'auth-flow');
      aw.seed();
      await aw.start({ SESSION_SECRET: 'qg-flow-secret', ALLOW_ORIGIN: FLOW_PAGE_ORIGIN });
      started.push(aw);

      const billSpec = { ...SURFACE.workers.billing, port: SURFACE.workers.billing.port + 60 };
      const bw = new Worker(ROOT, billSpec, 'billing-flow');
      bw.seed();
      await bw.start({
        ALLOW_ORIGIN: FLOW_PAGE_ORIGIN,
        STRIPE_API_BASE: stripeMock.base,
        STRIPE_SECRET_KEY: 'sk_test_quality_gate',
        STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET,
        STRIPE_PRICE_PRO_PER_REPO: 'price_qg_per_repo',
        STRIPE_PRICE_PRO_UNLIMITED: 'price_qg_unlimited',
      });
      started.push(bw);

      await run(results, ROOT, SURFACE.frontend_apps, aw, bw.base);
    }

    // ---------- The shipped CLI artefact ----------
    if (wants('cli')) {
      const { run } = await import('./suites/cli.mjs');
      await run(results, ROOT);
    }

    // ---------- Packaging surface ----------
    if (wants('packaging')) {
      const { run } = await import('./suites/packaging.mjs');
      await run(results, ROOT);
    }

    // ---------- The published Docker image ----------
    if (wants('docker')) {
      const { run } = await import('./suites/docker.mjs');
      await run(results, ROOT);
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
    if (sesMock) await sesMock.close();
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
