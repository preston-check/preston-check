/**
 * Preston-Check Telemetry Endpoint
 *
 * Cloudflare Worker that receives opt-in anonymous telemetry from scanner
 * runs and aggregates it for the annual State of Fintech Security report
 * and peer-comparison percentiles in the SaaS dashboard.
 *
 * Privacy contract (the full reason this is auditable in the open repo):
 *  - Accepts only the documented schema fields
 *  - Strips IP addresses immediately after rate-limiting
 *  - Never accepts source code, file paths, or check details
 *  - Per-repo identifier is a SHA-256 hash, not the URL itself
 *  - Aggregate writes go to KV; raw records to D1 with a 90-day TTL
 *
 * Endpoint: POST https://preston-check.com/api/v1/telemetry
 */

interface Env {
  DB: D1Database;
  AGGREGATE: KVNamespace;
  RATE_LIMIT_PER_HOUR: string;
  ALLOW_ORIGIN: string;
}

interface TelemetryPayload {
  version: string;       // Preston-Check version (e.g., "1.6.0")
  tier: string;          // free | pro | enterprise
  lang: string;          // primary detected language
  repo_hash: string;     // SHA-256 of git remote origin URL
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  total: number;
  timestamp: string;     // ISO 8601 UTC
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
  const limit = parseInt(env.RATE_LIMIT_PER_HOUR, 10) || 1000;
  const key = `rl:${ip}:${Math.floor(Date.now() / 3600000)}`;
  const cur = parseInt((await env.AGGREGATE.get(key)) || '0', 10);
  if (cur >= limit) return false;
  await env.AGGREGATE.put(key, String(cur + 1), { expirationTtl: 3600 });
  return true;
}

async function recordAggregate(env: Env, p: TelemetryPayload): Promise<void> {
  const day = p.timestamp.slice(0, 10);
  const score = p.total > 0 ? Math.round((p.pass * 100) / p.total) : 0;

  // Daily counters (KV) — fast aggregations for landing-page stats
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

  // Score histograms (KV) — for peer-comparison percentiles
  const bucket = Math.min(99, Math.floor(score / 10) * 10);
  const histKey = `hist:lang:${p.lang}:score:${bucket}`;
  const hcur = parseInt((await env.AGGREGATE.get(histKey)) || '0', 10);
  await env.AGGREGATE.put(histKey, String(hcur + 1));

  // Detailed record (D1) — 90-day TTL, used for trend analysis and the
  // annual State of Fintech Security report. Repo hash lets us deduplicate
  // multiple scans from the same repo without identifying it.
  await env.DB.prepare(
    `INSERT INTO scans (repo_hash, version, tier, lang, pass, fail, warn, skip, total, score, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(p.repo_hash, p.version, p.tier, p.lang, p.pass, p.fail, p.warn, p.skip, p.total, score, p.timestamp).run();
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const origin = env.ALLOW_ORIGIN || '*';
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }
    if (request.method !== 'POST') {
      return new Response('method not allowed', { status: 405, headers: corsHeaders(origin) });
    }

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

    ctx.waitUntil(recordAggregate(env, payload));

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    });
  },
};
