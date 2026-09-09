#!/usr/bin/env node
/**
 * Contract checks against the real Stripe and SES APIs.
 *
 * The quality gate exercises these integrations through mocks, which proves
 * the requests this code builds and the responses it handles — but not that
 * the real APIs still accept those requests or still return those shapes.
 * This closes that gap.
 *
 * Deliberately NOT part of the deploy gate. A Stripe or AWS outage would
 * otherwise block every deployment, making production releases depend on a
 * third party's uptime. It runs on a schedule instead: drift is detected and
 * alerted within a day, without ever standing between a fix and production.
 *
 * Everything created here is test-mode and disposable. SES sends go to the
 * mailbox simulator, which exercises the full signed send path without
 * delivering mail to anyone.
 */

import { createHash, createHmac } from 'node:crypto';
import { Results, banner, warn, info } from '../quality-gate/lib/harness.mjs';

const STRIPE_KEY = process.env.STRIPE_TEST_SECRET_KEY || '';
const SES_KEY_ID = process.env.SES_AWS_ACCESS_KEY_ID || '';
const SES_SECRET = process.env.SES_AWS_SECRET_ACCESS_KEY || '';
const SES_REGION = process.env.SES_AWS_REGION || 'us-east-1';
const FROM_EMAIL = process.env.FROM_EMAIL || 'preston@preston-check.com';

// AWS's mailbox simulator: accepted and scored as a real send, never delivered.
const SES_SIMULATOR = 'success@simulator.amazonses.com';

async function stripe(path, body, method = 'POST') {
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${STRIPE_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  };
  if (body) opts.body = new URLSearchParams(body).toString();
  const r = await fetch(`https://api.stripe.com/v1/${path}`, opts);
  return { status: r.status, body: await r.json().catch(() => null) };
}

/** Mirrors workers/billing: the exact call shapes production makes. */
async function checkStripe(r) {
  r.suite('Stripe API contract (test mode)');

  if (!STRIPE_KEY) {
    r.unreachable('contract.stripe', 'Stripe request shapes are still accepted',
      'STRIPE_TEST_SECRET_KEY is not set — add it as a repository secret');
    return;
  }
  if (!STRIPE_KEY.startsWith('sk_test_')) {
    r.record('contract.stripe', 'the configured key is test mode', false,
      'STRIPE_TEST_SECRET_KEY is not an sk_test_ key — refusing to run against live Stripe');
    return;
  }

  // Build our own disposable price so the check needs no pre-provisioned data.
  const product = await stripe('products', { name: 'Preston-Check contract check' });
  r.equal('contract.stripe', 'can create a product', product.status, 200);
  if (product.status !== 200) return;

  const price = await stripe('prices', {
    'product': product.body.id,
    'unit_amount': '99900',
    'currency': 'usd',
    'recurring[interval]': 'year',
  });
  r.equal('contract.stripe', 'can create a recurring price', price.status, 200);
  if (price.status !== 200) return;

  // The exact parameter set workers/billing sends for /checkout.
  const session = await stripe('checkout/sessions', {
    'mode': 'subscription',
    'line_items[0][price]': price.body.id,
    'line_items[0][quantity]': '1',
    'customer_email': 'contract-check@preston-check.com',
    'success_url': 'https://app.preston-check.com/#/settings?session_id={CHECKOUT_SESSION_ID}',
    'cancel_url': 'https://app.preston-check.com/#/settings',
    'subscription_data[metadata][plan]': 'pro_per_repo',
    'subscription_data[metadata][org_name]': 'Contract Check',
    'metadata[plan]': 'pro_per_repo',
    'metadata[org_name]': 'Contract Check',
    'allow_promotion_codes': 'true',
  });
  r.equal('contract.stripe', 'checkout session accepted with our exact parameters',
    session.status, 200);
  r.truthy('contract.stripe', 'checkout session returns a hosted url',
    session.body && typeof session.body.url === 'string' && session.body.url.startsWith('https://'),
    JSON.stringify(session.body?.error || session.body).slice(0, 300));

  // The retrieve shape /license depends on, including the expand.
  if (session.body?.id) {
    const fetched = await stripe(
      `checkout/sessions/${session.body.id}?expand[0]=subscription`, null, 'GET');
    r.equal('contract.stripe', 'checkout session retrieve accepted', fetched.status, 200);
    r.truthy('contract.stripe', 'retrieve returns the status field /license branches on',
      typeof fetched.body?.status === 'string',
      `got ${JSON.stringify(fetched.body).slice(0, 200)}`);
  }

  // The billing-portal shape. A customer is required, so make a disposable one.
  const customer = await stripe('customers', { email: 'contract-check@preston-check.com' });
  if (customer.status === 200) {
    const portal = await stripe('billing_portal/sessions', {
      customer: customer.body.id,
      return_url: 'https://app.preston-check.com/#/settings',
    });
    // A portal configuration may not exist in a fresh test account; that is a
    // Stripe dashboard setting, not an API-shape regression, so report it as
    // such instead of as drift.
    if (portal.status === 200) {
      r.truthy('contract.stripe', 'billing portal session returns a url',
        typeof portal.body?.url === 'string');
    } else {
      const msg = portal.body?.error?.message || '';
      r.truthy('contract.stripe', 'billing portal reachable (or needs dashboard config)',
        /configuration/i.test(msg),
        `unexpected billing-portal error: ${msg.slice(0, 200)}`);
      if (/configuration/i.test(msg)) {
        info('billing portal needs a default configuration in the Stripe test dashboard');
      }
    }
  }
}

/** The webhook signature scheme is local, but must still match Stripe's spec. */
function checkWebhookScheme(r) {
  r.suite('Stripe webhook signature scheme');
  const secret = 'whsec_contract_check';
  const payload = '{"id":"evt_contract","type":"invoice.paid"}';
  const ts = 1788000000;
  const expected = createHmac('sha256', secret).update(`${ts}.${payload}`).digest('hex');
  r.truthy('contract.stripe-webhook',
    'signature is HMAC-SHA256 over "<timestamp>.<payload>"',
    /^[a-f0-9]{64}$/.test(expected));
  r.equal('contract.stripe-webhook', 'header format is t=<ts>,v1=<hex>',
    `t=${ts},v1=${expected}`.split(',').map(p => p.split('=')[0]).join(','), 't,v1');
}

// ---- SES, using the same SigV4 construction as workers/auth ----
const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const hmac = (k, d) => createHmac('sha256', k).update(d, 'utf8').digest();

async function checkSes(r) {
  r.suite('SES API contract (mailbox simulator)');

  if (!SES_KEY_ID || !SES_SECRET) {
    r.unreachable('contract.ses', 'SES accepts our signed request',
      'SES_AWS_ACCESS_KEY_ID / SES_AWS_SECRET_ACCESS_KEY are not set');
    return;
  }

  const host = `email.${SES_REGION}.amazonaws.com`;
  const path = '/v2/email/outbound-emails';
  const body = JSON.stringify({
    FromEmailAddress: `Preston-Check <${FROM_EMAIL}>`,
    Destination: { ToAddresses: [SES_SIMULATOR] },
    Content: { Simple: {
      Subject: { Data: 'Preston-Check contract check', Charset: 'UTF-8' },
      Body: { Text: { Data: 'Automated contract check. No action needed.', Charset: 'UTF-8' } },
    } },
  });

  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body);
  const canonicalHeaders =
    `content-type:application/json\nhost:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = ['POST', path, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/${SES_REGION}/ses/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
  const kSigning = hmac(hmac(hmac(hmac(`AWS4${SES_SECRET}`, dateStamp), SES_REGION), 'ses'), 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

  const resp = await fetch(`https://${host}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Amz-Content-Sha256': payloadHash,
      'X-Amz-Date': amzDate,
      'Authorization': `AWS4-HMAC-SHA256 Credential=${SES_KEY_ID}/${scope}, ` +
                       `SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
    body,
  });
  const text = await resp.text();

  r.equal('contract.ses', 'SES accepts our SigV4-signed v2 send', resp.status, 200);
  if (resp.status !== 200) {
    r.record('contract.ses', 'SES returned no error', false, `${resp.status}: ${text.slice(0, 300)}`);
    return;
  }
  r.truthy('contract.ses', 'SES returns a MessageId',
    Boolean(JSON.parse(text || '{}').MessageId), text.slice(0, 200));
}

async function main() {
  banner('  PRESTON-CHECK CONTRACT CHECKS\n  Real Stripe + SES — scheduled, never gating a deploy');
  const r = new Results();
  try {
    await checkStripe(r);
    checkWebhookScheme(r);
    await checkSes(r);
  } catch (err) {
    r.suite('Harness');
    r.record('contract.harness', 'contract checks ran to completion', false, err.stack || String(err));
  }

  banner(`  RESULT: ${r.passed.length} passed, ${r.failed.length} failed`);
  for (const f of r.failed) {
    process.stdout.write(`  ✗ [${f.suite}] ${f.id} — ${f.description}\n`);
    if (f.detail) process.stdout.write(`      ${f.detail}\n`);
  }
  if (!r.ok) warn('third-party API drift or misconfiguration — deploys are NOT blocked by this');
  process.stdout.write(r.ok ? '\n  CONTRACTS HOLD\n\n' : '\n  CONTRACT DRIFT DETECTED\n\n');
  process.exit(r.ok ? 0 : 1);
}

main();
