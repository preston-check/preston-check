/**
 * Telemetry Worker acceptance suite.
 *
 * The worker writes via ctx.waitUntil, so the D1 row lands after the response
 * returns. The persistence assertion polls rather than asserting immediately —
 * a bare check races the write and fails intermittently, which is worse than
 * no check because it trains people to re-run the gate until it goes green.
 */

import { req, json, sleep } from '../lib/harness.mjs';

const jsonPost = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

function validPayload(repoHash) {
  return {
    repo_hash: repoHash,
    version: '1.8.426',
    tier: 'free',
    lang: 'shell',
    pass: 40, fail: 2, warn: 3, skip: 1, total: 46,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

export async function run(r, worker) {
  r.suite('Telemetry Worker (workers/telemetry)');
  const base = worker.base;

  r.status('telemetry.options', 'OPTIONS preflight returns 200',
    await req(base, '/', { method: 'OPTIONS' }), 200);
  r.status('telemetry.method-block', 'GET is refused with 405',
    await req(base, '/', { method: 'GET' }), 405);
  r.status('telemetry.bad-json', 'malformed JSON rejected',
    await req(base, '/', jsonPost('{nope')), 400);
  r.status('telemetry.bad-payload', 'structurally invalid payload rejected',
    await req(base, '/', jsonPost({ not: 'a scan' })), 400);

  const repoHash = `qg${Date.now()}`;
  const ok = await req(base, '/', jsonPost(validPayload(repoHash)));
  r.status('telemetry.ok', 'valid scan payload accepted', ok, 200);
  r.equal('telemetry.ok', 'responds { ok: true }', (await json(ok))?.ok, true);

  // waitUntil write — poll briefly rather than assume it has landed.
  let rows = [];
  for (let i = 0; i < 10 && rows.length === 0; i++) {
    await sleep(300);
    rows = worker.query(`SELECT repo_hash FROM scans WHERE repo_hash='${repoHash}'`);
  }
  r.truthy('telemetry.persists', 'scan row written to D1',
    rows.length >= 1, `no scans row for repo_hash=${repoHash} after 3s`);
}
