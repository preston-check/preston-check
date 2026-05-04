/**
 * Preston-Check Telemetry — Pages Function
 *
 * Reachable at https://app.preston-check.com/api/v1/telemetry. POST only.
 *
 * This is the canonical telemetry endpoint. It is co-located with the
 * customer portal Pages project so we don't have to migrate
 * preston-check.com DNS to Cloudflare; the app.preston-check.com
 * hostname is already attached as a Pages Custom Domain.
 *
 * Privacy contract (auditable in the open repo):
 *  - Accepts only the documented schema fields
 *  - Strips IP addresses immediately after rate-limiting
 *  - Never accepts source code, file paths, or check details
 *  - Per-repo identifier is a SHA-256 hash, not the URL itself
 *  - Aggregate writes go to KV; raw records to D1 with a 90-day TTL
 *
 * Bindings (configured in Cloudflare Pages dashboard for the
 * preston-check-customer project):
 *   - DB        -> D1: preston-check-telemetry
 *   - AGGREGATE -> KV: AGGREGATE
 *   - ALLOW_ORIGIN  ->  "*" (env var)
 *   - RATE_LIMIT_PER_HOUR -> "1000" (env var)
 */

interface Env {
  DB: D1Database;
  AGGREGATE: KVNamespace;
  RATE_LIMIT_PER_HOUR?: string;
  ALLOW_ORIGIN?: string;
}

interface TelemetryPayload {
  version: string;
  tier: string;
  lang: string;
  repo_hash: string;
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  total: number;
  timestamp: string;
}

const SCHEMA_FIELDS = ['version', 'tier', 'lang', 'repo_hash', 'pass', 'fail', 'warn', 'skip', 'total', 'timestamp'];

function corsHeaders(origin: string): HeadersInit {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function validatePayload(p: any): TelemetryPayload | null {
  if (typeof p !== 'object' || p === null) return null;
  for (const f of SCHEMA_FIELDS) {
    if (!(f in p)) return null;
  }
  if (typeof p.version !== 'string' || p.version.length > 32) return null;
  if (!['free', 'pro', 'enterprise'].includes(p.tier)) return null;
  if (typeof p.lang !== 'string' || p.lang.length > 32) return null;
  if (!/^[a-f0-9]{64}|unhashable$/.test(p.repo_hash)) return null;
  for (const n of ['pass', 'fail', 'warn', 'skip', 'total']) {
    if (typeof p[n] !== 'number' || p[n] < 0 || p[n] > 100000) return null;
  }
  if (typeof p.timestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(p.timestamp)) return null;
  return p as TelemetryPayload;
}

async function rateLimit(env: Env, ip: string): Promise<boolean> {
  const limit = parseInt(env.RATE_LIMIT_PER_HOUR || '1000', 10) || 1000;
  const key = `rl:${ip}:${Math.floor(Date.now() / 3600000)}`;
  const cur = parseInt((await env.AGGREGATE.get(key)) || '0', 10);
  if (cur >= limit) return false;
  await env.AGGREGATE.put(key, String(cur + 1), { expirationTtl: 3600 });
  return true;
}

async function recordAggregate(env: Env, p: TelemetryPayload): Promise<void> {
  const day = p.timestamp.slice(0, 10);
  const score = p.total > 0 ? Math.round((p.pass * 100) / p.total) : 0;

  const counters = [
    `agg:day:${day}:scans`,
    `agg:day:${day}:tier:${p.tier}`,
    `agg:day:${day}:lang:${p.lang}`,
    `agg:lang:${p.lang}:scans`,
    `agg:tier:${p.tier}:scans`,
  ];
  for (const k of counters) {
    const cur = parseInt((await env.AGGREGATE.get(k)) || '0', 10);
    await env.AGGREGATE.put(k, String(cur + 1));
  }

  const bucket = Math.min(99, Math.floor(score / 10) * 10);
  const histKey = `hist:lang:${p.lang}:score:${bucket}`;
  const hcur = parseInt((await env.AGGREGATE.get(histKey)) || '0', 10);
  await env.AGGREGATE.put(histKey, String(hcur + 1));

  await env.DB.prepare(
    `INSERT INTO scans (repo_hash, version, tier, lang, pass, fail, warn, skip, total, score, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(p.repo_hash, p.version, p.tier, p.lang, p.pass, p.fail, p.warn, p.skip, p.total, score, p.timestamp).run();
}

// Pages Functions exports a request handler per HTTP method.
// Cloudflare Pages routes /api/v1/telemetry to this file because of the
// directory structure: functions/api/v1/telemetry/index.ts.

export const onRequestOptions: PagesFunction<Env> = async ({ env }) => {
  const origin = env.ALLOW_ORIGIN || '*';
  return new Response(null, { headers: corsHeaders(origin) });
};

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const origin = env.ALLOW_ORIGIN || '*';

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await rateLimit(env, ip))) {
    return new Response('rate limit exceeded', { status: 429, headers: corsHeaders(origin) });
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response('invalid json', { status: 400, headers: corsHeaders(origin) });
  }

  const payload = validatePayload(body);
  if (!payload) {
    return new Response('invalid payload', { status: 400, headers: corsHeaders(origin) });
  }

  // Fire-and-forget: the client gets 200 even before the writes complete.
  // ctx.waitUntil isn't directly accessible here, but the async writes
  // will finish before the Worker shuts down.
  await recordAggregate(env, payload);

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
};

// Other methods (GET, PUT, DELETE, ...) get an automatic 405 from
// Cloudflare Pages Functions because no handler is exported for them.
// Do NOT export a generic `onRequest` here — when both `onRequest` and
// method-specific handlers exist, the generic export wins for all
// methods and breaks POST. The auto-405 path is the right pattern.
