/**
 * Preston-Check Auth Worker
 *
 * Magic-link + 6-digit-code authentication for app.preston-check.com.
 *
 *  POST /request-code   { email }                → 200 { sent: true }
 *    Issues a 6-digit code, stores in KV with 10-min TTL, sends via Resend.
 *    Rate-limited per email (3 codes per 15 min).
 *
 *  POST /verify-code    { email, code }          → 200 { ok, session_token }
 *    Validates the code, creates a session in D1, returns a session token.
 *    Token is a signed cookie payload; client stores in HttpOnly cookie
 *    (set by this Worker) and an Authorization header echo for cross-domain.
 *
 *  GET  /me                                      → 200 { account } | 401
 *    Returns the authenticated account from the session token.
 *
 *  POST /logout                                  → 200 { ok }
 *    Deletes the session row and clears the cookie.
 *
 * Email delivery:
 *  When RESEND_API_KEY is set, codes are sent via the Resend API.
 *  When RESEND_API_KEY is absent, codes are written to D1 with a marker
 *  for operator-side delivery (debug log via `wrangler tail`). This keeps
 *  development unblocked when no email service is configured.
 */

interface Env {
  DB: D1Database;
  CODES: KVNamespace;
  ALLOW_ORIGIN: string;
  SESSION_TTL_DAYS: string;
  CODE_TTL_MINUTES: string;
  FROM_EMAIL: string;
  FROM_NAME: string;
  RESEND_API_KEY?: string;
  SESSION_SECRET?: string;
}

function corsHeaders(origin: string): HeadersInit {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

function isValidEmail(s: string): boolean {
  return typeof s === 'string'
    && s.length <= 200
    && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
}

function sixDigitCode(): string {
  // Cryptographically random 6-digit code, zero-padded
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  const num = (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)) >>> 0;
  return String(num % 1000000).padStart(6, '0');
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------- Email delivery ----------------

async function sendCodeEmail(env: Env, email: string, code: string): Promise<{ delivered: boolean; via: string }> {
  // If Resend is configured, use it. Otherwise write a "manual delivery"
  // marker that the operator can read via `wrangler tail` in dev.
  if (!env.RESEND_API_KEY) {
    console.log(`[manual-delivery] code=${code} email=${email}`);
    return { delivered: false, via: 'manual' };
  }

  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: `${env.FROM_NAME} <${env.FROM_EMAIL}>`,
      to: [email],
      subject: 'Your Preston-Check sign-in code',
      text: `Your Preston-Check sign-in code is: ${code}\n\nThis code expires in ${env.CODE_TTL_MINUTES} minutes. If you did not request it, you can ignore this email.\n\n— Preston-Check`,
      html: `<p style="font-family: ui-sans-serif, system-ui, sans-serif; color:#0B1F3A; max-width: 480px; margin: 32px auto; line-height: 1.6;">Your Preston-Check sign-in code:</p><p style="font-family: ui-monospace, monospace; font-size: 32px; letter-spacing: 8px; font-weight: 700; color:#10B981; max-width: 480px; margin: 16px auto 32px; text-align: center;">${code}</p><p style="font-family: ui-sans-serif, system-ui, sans-serif; color:#475569; max-width: 480px; margin: 0 auto; font-size: 14px; line-height: 1.6;">This code expires in ${env.CODE_TTL_MINUTES} minutes. If you did not request it, you can ignore this email.</p><p style="font-family: ui-sans-serif, system-ui, sans-serif; color:#94A3B8; max-width: 480px; margin: 32px auto 0; font-size: 12px;">— Preston-Check<br/>https://preston-check.com</p>`,
    }),
  });

  if (!r.ok) {
    const text = await r.text();
    console.log(`[resend-error] status=${r.status} body=${text}`);
    return { delivered: false, via: 'resend-error' };
  }
  return { delivered: true, via: 'resend' };
}

// ---------------- Endpoints ----------------

async function handleRequestCode(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  let body: any;
  try { body = await request.json(); } catch {
    return new Response('invalid json', { status: 400, headers: corsHeaders(origin) });
  }
  const email = String(body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) {
    return new Response('invalid email', { status: 400, headers: corsHeaders(origin) });
  }

  // Rate limit: 3 codes per 15 min per email
  const rlKey = `rl:request-code:${email}:${Math.floor(Date.now() / 900000)}`;
  const cur = parseInt((await env.CODES.get(rlKey)) || '0', 10);
  if (cur >= 3) {
    return new Response('too many requests; wait 15 minutes', { status: 429, headers: corsHeaders(origin) });
  }
  await env.CODES.put(rlKey, String(cur + 1), { expirationTtl: 900 });

  const code = sixDigitCode();
  const ttl = (parseInt(env.CODE_TTL_MINUTES, 10) || 10) * 60;
  await env.CODES.put(`code:${email}`, code, { expirationTtl: ttl });

  const result = await sendCodeEmail(env, email, code);
  return new Response(JSON.stringify({ sent: result.delivered, via: result.via }), {
    status: 200,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
}

async function handleVerifyCode(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  let body: any;
  try { body = await request.json(); } catch {
    return new Response('invalid json', { status: 400, headers: corsHeaders(origin) });
  }
  const email = String(body.email || '').trim().toLowerCase();
  const code = String(body.code || '').trim();
  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return new Response('invalid email or code', { status: 400, headers: corsHeaders(origin) });
  }

  const stored = await env.CODES.get(`code:${email}`);
  if (!stored) {
    return new Response('code expired', { status: 401, headers: corsHeaders(origin) });
  }
  // Constant-time compare
  if (stored.length !== code.length) {
    return new Response('invalid code', { status: 401, headers: corsHeaders(origin) });
  }
  let mismatch = 0;
  for (let i = 0; i < code.length; i++) mismatch |= stored.charCodeAt(i) ^ code.charCodeAt(i);
  if (mismatch !== 0) {
    return new Response('invalid code', { status: 401, headers: corsHeaders(origin) });
  }

  // Code consumed — delete from KV
  await env.CODES.delete(`code:${email}`);

  // Upsert account
  await env.DB.prepare(
    'INSERT INTO accounts (email) VALUES (?) ON CONFLICT(email) DO UPDATE SET last_login_at = strftime(\'%s\',\'now\')'
  ).bind(email).run();

  const acct = await env.DB.prepare(
    'SELECT id, email, org_name FROM accounts WHERE email = ?'
  ).bind(email).first<{ id: number; email: string; org_name: string | null }>();
  if (!acct) {
    return new Response('account upsert failed', { status: 500, headers: corsHeaders(origin) });
  }

  // Create session
  const sid = randomHex(32);
  const ttlDays = parseInt(env.SESSION_TTL_DAYS, 10) || 30;
  const expiresAt = Math.floor(Date.now() / 1000) + ttlDays * 86400;
  const ipHash = await sha256Hex((request.headers.get('CF-Connecting-IP') || '') + (env.SESSION_SECRET || ''));
  await env.DB.prepare(
    'INSERT INTO sessions (id, account_id, email, expires_at, user_agent, ip_hash) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(sid, acct.id, email, expiresAt, (request.headers.get('User-Agent') || '').slice(0, 200), ipHash).run();

  // Set HttpOnly cookie + return token in body
  const cookie = `pc_session=${sid}; Path=/; Max-Age=${ttlDays * 86400}; HttpOnly; Secure; SameSite=None; Domain=preston-check.com`;
  return new Response(JSON.stringify({
    ok: true,
    session_token: sid,
    account: { id: acct.id, email: acct.email, org_name: acct.org_name }
  }), {
    status: 200,
    headers: {
      ...corsHeaders(origin),
      'Content-Type': 'application/json',
      'Set-Cookie': cookie,
    },
  });
}

async function getSession(request: Request, env: Env): Promise<{ id: number; email: string; org_name: string | null } | null> {
  // Accept session_token from Authorization: Bearer header OR pc_session cookie
  let sid = '';
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) sid = auth.slice(7).trim();
  if (!sid) {
    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/pc_session=([a-f0-9]{64})/);
    if (m) sid = m[1];
  }
  if (!/^[a-f0-9]{64}$/.test(sid)) return null;

  const row = await env.DB.prepare(
    `SELECT a.id, a.email, a.org_name, s.expires_at
     FROM sessions s JOIN accounts a ON a.id = s.account_id
     WHERE s.id = ?`
  ).bind(sid).first<{ id: number; email: string; org_name: string | null; expires_at: number }>();
  if (!row) return null;
  if (row.expires_at < Math.floor(Date.now() / 1000)) return null;
  return { id: row.id, email: row.email, org_name: row.org_name };
}

async function handleMe(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  const acct = await getSession(request, env);
  if (!acct) {
    return new Response(JSON.stringify({ error: 'unauthenticated' }), {
      status: 401, headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({ account: acct }), {
    status: 200, headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  let sid = '';
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) sid = auth.slice(7).trim();
  if (sid && /^[a-f0-9]{64}$/.test(sid)) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run();
  }
  const cookie = `pc_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None; Domain=preston-check.com`;
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json', 'Set-Cookie': cookie },
  });
}

// ---------------- Entry point ----------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = env.ALLOW_ORIGIN;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    if (url.pathname === '/request-code' && request.method === 'POST') {
      return handleRequestCode(request, env);
    }
    if (url.pathname === '/verify-code' && request.method === 'POST') {
      return handleVerifyCode(request, env);
    }
    if (url.pathname === '/me' && request.method === 'GET') {
      return handleMe(request, env);
    }
    if (url.pathname === '/logout' && request.method === 'POST') {
      return handleLogout(request, env);
    }

    return new Response('not found', { status: 404, headers: corsHeaders(origin) });
  },
};
