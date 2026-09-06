/**
 * Stripe test double + webhook signing.
 *
 * The signing helper reproduces Stripe's real scheme (HMAC-SHA256 over
 * "<timestamp>.<payload>", header "t=..,v1=.."), so the Worker's signature
 * verification is exercised for real rather than stubbed out. A webhook test
 * that bypasses signature checking would pass while the deployed Worker
 * rejected every live event.
 */

import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';

export const WEBHOOK_SECRET = 'whsec_quality_gate_fixture_secret';

/** Build a Stripe-format signature header for a raw payload. */
export function signPayload(payload, secret = WEBHOOK_SECRET, timestamp = Math.floor(Date.now() / 1000)) {
  const mac = createHmac('sha256', secret).update(`${timestamp}.${payload}`).digest('hex');
  return `t=${timestamp},v1=${mac}`;
}

let eventCounter = 0;
/** A minimal but structurally real Stripe event envelope. */
export function makeEvent(type, object = {}) {
  eventCounter += 1;
  return {
    id: `evt_qg_${Date.now()}_${eventCounter}`,
    object: 'event',
    type,
    livemode: false,
    created: Math.floor(Date.now() / 1000),
    data: { object },
  };
}

/** Representative data objects per event type, shaped like Stripe's. */
export function objectFor(type) {
  const customer = 'cus_QGtest123456';
  const base = { id: 'obj_qg', customer, metadata: { plan: 'pro_per_repo', org_name: 'QG Org' } };
  if (type === 'checkout.session.completed') {
    return {
      ...base,
      id: 'cs_test_qg_completed',
      object: 'checkout_session',
      customer_email: 'gate@preston-check.com',
      customer_details: { email: 'gate@preston-check.com' },
      subscription: 'sub_qg_123',
      status: 'complete',
      amount_total: 99900,
      currency: 'usd',
    };
  }
  if (type.startsWith('customer.subscription.')) {
    return {
      ...base,
      id: 'sub_qg_123',
      object: 'subscription',
      status: type.endsWith('deleted') ? 'canceled' : 'active',
      current_period_end: Math.floor(Date.now() / 1000) + 365 * 86400,
      items: { data: [{ price: { id: 'price_qg', unit_amount: 99900 } }] },
    };
  }
  // invoice.*
  return {
    ...base,
    id: 'in_qg_123',
    object: 'invoice',
    subscription: 'sub_qg_123',
    customer_email: 'gate@preston-check.com',
    amount_paid: type === 'invoice.paid' ? 99900 : 0,
    amount_due: 99900,
    status: type === 'invoice.paid' ? 'paid' : 'open',
    currency: 'usd',
  };
}

/**
 * Local stand-in for api.stripe.com. Returns success shapes for the three
 * endpoints the billing Worker calls. Pointed at via STRIPE_API_BASE, which
 * exists in the Worker solely for this purpose and is never set in production.
 */
export function startStripeMock(port) {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const url = req.url || '';
      const reply = (obj, code = 200) => {
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(obj));
      };

      if (url.startsWith('/v1/checkout/sessions/')) {
        // Session lookup used by /license. "cs_test_incomplete" models a
        // checkout the customer abandoned, which must not yield a license.
        const id = url.split('/v1/checkout/sessions/')[1].split('?')[0];
        if (id === 'cs_test_incomplete') {
          return reply({ id, status: 'open', subscription: null });
        }
        return reply({
          id,
          status: 'complete',
          customer: 'cus_QGtest123456',
          customer_email: 'gate@preston-check.com',
          subscription: {
            id: 'sub_qg_123',
            current_period_end: Math.floor(Date.now() / 1000) + 365 * 86400,
          },
        });
      }
      if (url.startsWith('/v1/checkout/sessions')) {
        return reply({ id: 'cs_test_qg_new', url: 'https://checkout.stripe.com/c/pay/cs_test_qg_new' });
      }
      if (url.startsWith('/v1/billing_portal/sessions')) {
        return reply({ id: 'bps_qg', url: 'https://billing.stripe.com/p/session/qg' });
      }
      return reply({ error: { message: `unmocked stripe path: ${url}` } }, 404);
    });
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({
      base: `http://127.0.0.1:${port}`,
      close: () => new Promise(r => server.close(r)),
    }));
  });
}
