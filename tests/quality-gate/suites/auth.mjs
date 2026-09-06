/**
 * Auth Worker acceptance suite.
 *
 * Exercises the full sign-in lifecycle against the real Worker on real local
 * D1 + KV: request a code, read it back out of KV, verify it, use the session
 * over both Bearer and cookie transports, then log out and prove the session
 * is actually gone rather than merely reported gone.
 */

import { req, json } from '../lib/harness.mjs';

const EMAIL = 'gate@preston-check.com';
const jsonPost = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

export async function run(r, worker) {
  r.suite('Auth Worker (workers/auth)');
  const base = worker.base;

  // --- CORS preflight ---
  const opt = await req(base, '/request-code', { method: 'OPTIONS' });
  r.status('auth.options', 'OPTIONS preflight returns 200', opt, 200);
  r.truthy('auth.options', 'preflight carries Access-Control-Allow-Origin',
    opt.headers.get('access-control-allow-origin'));

  // --- /request-code validation ---
  r.status('auth.request-code.bad-json', 'malformed JSON rejected',
    await req(base, '/request-code', jsonPost('{not json')), 400);
  r.status('auth.request-code.bad-email', 'malformed e-mail rejected',
    await req(base, '/request-code', jsonPost({ email: 'nope' })), 400);

  // --- /request-code happy path ---
  const rc = await req(base, '/request-code', jsonPost({ email: EMAIL }));
  r.status('auth.request-code.ok', 'valid e-mail accepted', rc, 200);
  const rcBody = await json(rc);
  r.truthy('auth.request-code.ok', 'response reports a delivery channel', rcBody && rcBody.via);

  // The code must actually exist in KV — proves the write, not just the 200.
  const code = worker.kvGet('CODES', `code:${EMAIL}`);
  r.truthy('auth.request-code.ok', 'six-digit code persisted to KV',
    code && /^\d{6}$/.test(code), `KV held ${JSON.stringify(code)}`);

  // --- /verify-code validation ---
  r.status('auth.verify-code.bad-json', 'malformed JSON rejected',
    await req(base, '/verify-code', jsonPost('{bad')), 400);
  r.status('auth.verify-code.bad-format', 'non-6-digit code rejected',
    await req(base, '/verify-code', jsonPost({ email: EMAIL, code: 'abc' })), 400);
  r.status('auth.verify-code.expired', 'unknown e-mail treated as expired',
    await req(base, '/verify-code', jsonPost({ email: 'nobody@preston-check.com', code: '123456' })), 401);

  const wrong = String((Number(code) + 1) % 1000000).padStart(6, '0');
  r.status('auth.verify-code.wrong', 'incorrect code rejected',
    await req(base, '/verify-code', jsonPost({ email: EMAIL, code: wrong })), 401);

  // --- /verify-code happy path ---
  const vc = await req(base, '/verify-code', jsonPost({ email: EMAIL, code }));
  r.status('auth.verify-code.ok', 'correct code establishes a session', vc, 200);
  const vcBody = await json(vc);
  const token = vcBody && vcBody.session_token;
  r.truthy('auth.verify-code.ok', 'session_token returned', token && /^[a-f0-9]{64}$/.test(token));
  r.contains('auth.verify-code.ok', 'HttpOnly session cookie set',
    vc.headers.get('set-cookie') || '', 'HttpOnly');

  // Session and account rows must exist in D1.
  const accounts = worker.query(`SELECT email FROM accounts WHERE email='${EMAIL}'`);
  r.truthy('auth.verify-code.ok', 'account row upserted in D1', accounts.length === 1);

  // Code is single-use: KV entry must be gone after a successful verify.
  r.truthy('auth.verify-code.ok', 'code consumed from KV after use',
    !worker.kvGet('CODES', `code:${EMAIL}`));

  // --- /me ---
  r.status('auth.me.anon', 'unauthenticated /me is 401',
    await req(base, '/me', { method: 'GET' }), 401);
  r.status('auth.me.malformed-token', 'malformed bearer token is 401',
    await req(base, '/me', { method: 'GET', headers: { Authorization: 'Bearer not-a-token' } }), 401);

  const meBearer = await req(base, '/me', {
    method: 'GET', headers: { Authorization: `Bearer ${token}` },
  });
  r.status('auth.me.bearer', '/me accepts Bearer token', meBearer, 200);
  const meBody = await json(meBearer);
  r.equal('auth.me.bearer', '/me returns the signed-in account',
    meBody && meBody.account && meBody.account.email, EMAIL);

  const meCookie = await req(base, '/me', {
    method: 'GET', headers: { Cookie: `pc_session=${token}` },
  });
  r.status('auth.me.cookie', '/me accepts session cookie', meCookie, 200);

  // --- /logout, and proof it actually invalidated the session ---
  const lo = await req(base, '/logout', {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
  });
  r.status('auth.logout.ok', 'logout returns 200', lo, 200);
  r.contains('auth.logout.ok', 'logout clears the cookie',
    lo.headers.get('set-cookie') || '', 'Max-Age=0');

  const afterLogout = await req(base, '/me', {
    method: 'GET', headers: { Authorization: `Bearer ${token}` },
  });
  r.status('auth.logout.invalidates', 'session unusable after logout', afterLogout, 401);

  // --- rate limit: 3 codes per 15 min, so the 4th must be refused ---
  const rlEmail = 'ratelimit@preston-check.com';
  let rlStatus = 0;
  for (let i = 0; i < 4; i++) {
    const resp = await req(base, '/request-code', jsonPost({ email: rlEmail }));
    rlStatus = resp.status;
  }
  r.equal('auth.request-code.ratelimit', '4th code request within window is 429', rlStatus, 429);

  // --- unknown route ---
  r.status('auth.notfound', 'unknown path is 404',
    await req(base, '/nope', { method: 'GET' }), 404);
}
