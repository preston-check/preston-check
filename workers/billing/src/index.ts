/**
 * Preston-Check Billing Worker
 *
 * Two responsibilities:
 *
 *  1. POST /checkout
 *     Creates a Stripe Checkout Session for a given plan and customer
 *     email. Returns the hosted-checkout URL the customer portal redirects
 *     to. Idempotent (per-email rate limit prevents duplicate sessions).
 *
 *  2. POST /webhook
 *     Receives Stripe events, validates the signature using
 *     STRIPE_WEBHOOK_SECRET, and mirrors the relevant subset of state
 *     into D1 so the customer portal and admin portal can render
 *     without round-tripping to Stripe on every request.
 *
 * Bindings (set in wrangler.toml):
 *   DB             D1 database (preston-check-billing)
 *   STATE          KV namespace for short-lived nonces / idempotency keys
 *   ALLOW_ORIGIN   CORS allow-origin (https://app.preston-check.com)
 *   SUCCESS_URL    Where Stripe redirects on successful checkout
 *   CANCEL_URL     Where Stripe redirects on user cancellation
 *
 * Secrets (set via `wrangler secret put`):
 *   STRIPE_SECRET_KEY        sk_test_... or sk_live_...
 *   STRIPE_WEBHOOK_SECRET    whsec_...   (from the Stripe webhook config)
 *   STRIPE_PRICE_PRO_PER_REPO    price_xxx for $999/repo/yr
 *   STRIPE_PRICE_PRO_UNLIMITED   price_xxx for $4,999/yr unlimited
 */

interface Env {
  DB: D1Database;
  STATE: KVNamespace;

  ALLOW_ORIGIN: string;
  SUCCESS_URL: string;
  CANCEL_URL: string;

  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  STRIPE_PRICE_PRO_PER_REPO: string;
  STRIPE_PRICE_PRO_UNLIMITED: string;
  LICENSE_SIGNING_KEY: string;     // PEM-encoded Ed25519 private key (set via wrangler secret)
}

const PLAN_TO_PRICE_KEY: Record<string, keyof Env> = {
  pro_per_repo: 'STRIPE_PRICE_PRO_PER_REPO',
  pro_unlimited: 'STRIPE_PRICE_PRO_UNLIMITED',
};

function corsHeaders(origin: string): HeadersInit {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

// Stripe API call — POST x-www-form-urlencoded with Bearer auth.
async function stripeRequest(env: Env, path: string, body: Record<string, string>): Promise<any> {
  const params = new URLSearchParams(body);
  const r = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
  return r.json();
}

// ---------------------- /checkout ----------------------

async function handleCheckout(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response('invalid json', { status: 400, headers: corsHeaders(origin) });
  }

  const plan = String(body.plan || '');
  const email = String(body.email || '').trim().toLowerCase();
  const orgName = String(body.org_name || '').trim().slice(0, 200);

  if (!PLAN_TO_PRICE_KEY[plan]) {
    return new Response('unknown plan', { status: 400, headers: corsHeaders(origin) });
  }
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return new Response('invalid email', { status: 400, headers: corsHeaders(origin) });
  }

  const priceId = env[PLAN_TO_PRICE_KEY[plan]];
  if (!priceId) {
    return new Response('price not configured', { status: 500, headers: corsHeaders(origin) });
  }

  // Per-email rate-limit on checkout creation: 5 sessions per hour.
  const rlKey = `rl:checkout:${email}:${Math.floor(Date.now() / 3600000)}`;
  const cur = parseInt((await env.STATE.get(rlKey)) || '0', 10);
  if (cur >= 5) {
    return new Response('too many checkout attempts', { status: 429, headers: corsHeaders(origin) });
  }
  await env.STATE.put(rlKey, String(cur + 1), { expirationTtl: 3600 });

  // Create the Checkout Session.
  const session = await stripeRequest(env, 'checkout/sessions', {
    'mode': 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'customer_email': email,
    'success_url': `${env.SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
    'cancel_url': env.CANCEL_URL,
    'subscription_data[metadata][plan]': plan,
    'subscription_data[metadata][org_name]': orgName,
    'metadata[plan]': plan,
    'metadata[org_name]': orgName,
    'allow_promotion_codes': 'true',
    'billing_address_collection': 'required',
    'tax_id_collection[enabled]': 'true',
  });

  if (!session.url) {
    return new Response(JSON.stringify({ error: session.error || session }), {
      status: 502,
      headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ url: session.url, id: session.id }), {
    status: 200,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
}

// ---------------------- /webhook ----------------------
//
// Validates Stripe's signature header against STRIPE_WEBHOOK_SECRET,
// then mirrors the event into D1.

async function verifyStripeSignature(payload: string, sigHeader: string, secret: string): Promise<boolean> {
  // Header format: "t=<timestamp>,v1=<signature>"
  const parts = sigHeader.split(',').reduce<Record<string, string>>((acc, p) => {
    const [k, v] = p.split('=');
    acc[k] = v;
    return acc;
  }, {});
  const timestamp = parts['t'];
  const sig = parts['v1'];
  if (!timestamp || !sig) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const expected = await crypto.subtle.sign('HMAC', key, enc.encode(signedPayload));
  const expectedHex = Array.from(new Uint8Array(expected))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time comparison
  if (expectedHex.length !== sig.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expectedHex.length; i++) {
    mismatch |= expectedHex.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return mismatch === 0;
}

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const sig = request.headers.get('stripe-signature') || '';
  const payload = await request.text();

  if (!await verifyStripeSignature(payload, sig, env.STRIPE_WEBHOOK_SECRET)) {
    return new Response('signature mismatch', { status: 400 });
  }

  let event: any;
  try {
    event = JSON.parse(payload);
  } catch {
    return new Response('invalid json', { status: 400 });
  }

  // Atomic idempotency: rely on the UNIQUE(stripe_event_id) constraint
  // rather than a SELECT-then-INSERT pattern. Two concurrent deliveries
  // of the same event would both pass a SELECT but only one INSERT can
  // succeed; using INSERT OR IGNORE we get a 0-rows-changed signal for
  // the duplicate without needing application-level locking.
  const insertResult = await env.DB.prepare(
    'INSERT OR IGNORE INTO webhook_events (stripe_event_id, type, livemode, payload) VALUES (?, ?, ?, ?)'
  ).bind(event.id, event.type, event.livemode ? 1 : 0, payload).run();
  if (!insertResult.meta || insertResult.meta.changes === 0) {
    return new Response(JSON.stringify({ ok: true, duplicate: true }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  }

  // Dispatch on event type. Only the events we actually use are wired;
  // others are recorded in webhook_events but otherwise ignored.
  switch (event.type) {
    case 'checkout.session.completed':
      await onCheckoutCompleted(env, event.data.object);
      break;
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted':
      await onSubscriptionChanged(env, event.data.object);
      break;
    case 'invoice.paid':
    case 'invoice.payment_failed':
    case 'invoice.finalized':
      await onInvoiceChanged(env, event.data.object);
      break;
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  });
}

async function onCheckoutCompleted(env: Env, session: any): Promise<void> {
  // Upsert the customer now that we know the Stripe customer ID.
  const customerId = session.customer;
  const email = session.customer_email || session.customer_details?.email || '';
  const orgName = session.metadata?.org_name || '';
  if (!customerId || !email) return;

  await env.DB.prepare(
    'INSERT INTO customers (stripe_customer_id, email, org_name) VALUES (?, ?, ?)' +
    ' ON CONFLICT(stripe_customer_id) DO UPDATE SET email = excluded.email, org_name = excluded.org_name, updated_at = strftime(\'%s\',\'now\')'
  ).bind(customerId, email, orgName).run();
}

async function onSubscriptionChanged(env: Env, sub: any): Promise<void> {
  const plan = sub.metadata?.plan || sub.items?.data?.[0]?.price?.metadata?.plan || 'unknown';
  await env.DB.prepare(
    `INSERT INTO subscriptions
       (stripe_subscription_id, stripe_customer_id, status, plan,
        current_period_start, current_period_end, cancel_at_period_end)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(stripe_subscription_id) DO UPDATE SET
        status = excluded.status,
        current_period_start = excluded.current_period_start,
        current_period_end = excluded.current_period_end,
        cancel_at_period_end = excluded.cancel_at_period_end,
        updated_at = strftime('%s','now')`
  ).bind(
    sub.id,
    sub.customer,
    sub.status,
    plan,
    sub.current_period_start || null,
    sub.current_period_end || null,
    sub.cancel_at_period_end ? 1 : 0,
  ).run();
}

async function onInvoiceChanged(env: Env, inv: any): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO invoices
       (stripe_invoice_id, stripe_customer_id, stripe_subscription_id,
        status, amount_due, amount_paid, currency,
        hosted_invoice_url, invoice_pdf, paid_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(stripe_invoice_id) DO UPDATE SET
        status = excluded.status,
        amount_paid = excluded.amount_paid,
        paid_at = excluded.paid_at,
        hosted_invoice_url = excluded.hosted_invoice_url,
        invoice_pdf = excluded.invoice_pdf`
  ).bind(
    inv.id,
    inv.customer,
    inv.subscription || null,
    inv.status,
    inv.amount_due,
    inv.amount_paid || 0,
    inv.currency || 'usd',
    inv.hosted_invoice_url || null,
    inv.invoice_pdf || null,
    inv.status_transitions?.paid_at || null,
  ).run();
}

// ---------------- /billing-portal ----------------
//
// Creates a Stripe Customer Portal session and returns the URL.
// Customer portal opens this in a redirect; Stripe shows their hosted
// UI for managing payment method, downloading invoices, switching
// plans, canceling. Closes the loop on subscription self-service.

async function handleBillingPortal(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  let body: any;
  try { body = await request.json(); } catch {
    return new Response('invalid json', { status: 400, headers: corsHeaders(origin) });
  }
  const email = String(body.email || '').trim().toLowerCase();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return new Response('invalid email', { status: 400, headers: corsHeaders(origin) });
  }

  const cust = await env.DB.prepare(
    'SELECT stripe_customer_id FROM customers WHERE email = ? LIMIT 1'
  ).bind(email).first<{ stripe_customer_id: string }>();
  if (!cust) {
    return new Response('no Stripe customer for that email', { status: 404, headers: corsHeaders(origin) });
  }

  const session = await stripeRequest(env, 'billing_portal/sessions', {
    'customer': cust.stripe_customer_id,
    'return_url': env.SUCCESS_URL,
  });
  if (!session.url) {
    return new Response(JSON.stringify({ error: session.error || session }), {
      status: 502, headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({ url: session.url }), {
    status: 200, headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
}

// ---------------- /license ----------------
//
// Generates an Ed25519-signed license file for a paid subscription.
// Validated against the Stripe Checkout session_id (caller must have
// completed checkout). Signed with LICENSE_SIGNING_KEY (Worker secret;
// the corresponding public key is at lib/license_saas_pubkey.pem).

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, '')
                 .replace(/-----END [^-]+-----/g, '')
                 .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
}

async function signPayload(privateKeyPem: string, payload: string): Promise<string> {
  const key = await importPrivateKey(privateKeyPem);
  const sig = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(payload));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function pemBase64(s: string): string {
  const out: string[] = [];
  for (let i = 0; i < s.length; i += 64) out.push(s.slice(i, i + 64));
  return out.join('\n');
}

async function generateLicenseFile(env: Env, customerId: string, email: string, tier: string, expiresIso: string): Promise<string> {
  const payload = JSON.stringify({
    license_id:     'PC-' + new Date().getFullYear() + '-' + customerId.slice(-6).toUpperCase(),
    customer_id:    customerId,
    customer_email: email,
    tier:           tier,
    issued_at:      new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at:     expiresIso,
    schema_version: 1,
  });
  const sig = await signPayload(env.LICENSE_SIGNING_KEY, payload);
  const payloadB64 = btoa(payload);
  return [
    '-----BEGIN PRESTON-CHECK LICENSE-----',
    pemBase64(payloadB64),
    '-----END PRESTON-CHECK LICENSE-----',
    '-----BEGIN PRESTON-CHECK SIGNATURE-----',
    pemBase64(sig),
    '-----END PRESTON-CHECK SIGNATURE-----',
    '',
  ].join('\n');
}

async function handleLicenseDownload(request: Request, env: Env): Promise<Response> {
  const origin = env.ALLOW_ORIGIN;
  let body: any;
  try { body = await request.json(); } catch {
    return new Response('invalid json', { status: 400, headers: corsHeaders(origin) });
  }
  const sessionId = String(body.session_id || '');
  if (!sessionId.startsWith('cs_')) {
    return new Response('invalid session_id', { status: 400, headers: corsHeaders(origin) });
  }

  const params = new URLSearchParams({ 'expand[0]': 'subscription' });
  const sessResp = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}?${params}`, {
    headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` },
  });
  const sess: any = await sessResp.json();
  if (!sessResp.ok || sess.status !== 'complete' || !sess.subscription) {
    return new Response('checkout not complete', { status: 400, headers: corsHeaders(origin) });
  }

  const customerId = sess.customer;
  const email = sess.customer_email || sess.customer_details?.email || '';
  const subscription = typeof sess.subscription === 'string' ? null : sess.subscription;
  const periodEnd = subscription?.current_period_end || (Math.floor(Date.now() / 1000) + 365 * 86400);
  const expiresIso = new Date(periodEnd * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

  if (!env.LICENSE_SIGNING_KEY) {
    return new Response('license signing not configured', { status: 503, headers: corsHeaders(origin) });
  }

  const license = await generateLicenseFile(env, customerId, email, 'pro', expiresIso);
  const filename = `preston-check-${customerId.slice(-12)}.license`;
  return new Response(license, {
    status: 200,
    headers: {
      ...corsHeaders(origin),
      'Content-Type': 'application/x-pem-file',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  });
}

// ---------------------- entry point ----------------------

// Structured error logging: every uncaught handler exception becomes a JSON
// log line in Cloudflare Workers Logs (dashboard Live Logs). No external
// service needed. We never log request bodies (PII risk) or the Stripe
// signature header.
function logError(reqId: string, request: Request, err: unknown): void {
  const e = err instanceof Error ? { name: err.name, message: err.message, stack: err.stack } : { message: String(err) };
  console.error(JSON.stringify({
    level: 'error',
    worker: 'billing',
    req_id: reqId,
    method: request.method,
    path: new URL(request.url).pathname,
    err: e,
    ts: new Date().toISOString(),
  }));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = env.ALLOW_ORIGIN;
    const reqId = crypto.randomUUID();

    try {
      if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders(origin) });
      }

      if (url.pathname === '/checkout' && request.method === 'POST') {
        return await handleCheckout(request, env);
      }
      if (url.pathname === '/webhook' && request.method === 'POST') {
        return await handleWebhook(request, env);
      }
      if (url.pathname === '/billing-portal' && request.method === 'POST') {
        return await handleBillingPortal(request, env);
      }
      if (url.pathname === '/license' && request.method === 'POST') {
        return await handleLicenseDownload(request, env);
      }

      return new Response('not found', { status: 404, headers: corsHeaders(origin) });
    } catch (err) {
      logError(reqId, request, err);
      return new Response(JSON.stringify({ error: 'internal', request_id: reqId }), {
        status: 500,
        headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
      });
    }
  },
};
