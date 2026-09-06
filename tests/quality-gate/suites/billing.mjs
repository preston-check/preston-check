/**
 * Billing Worker acceptance suite (non-webhook routes).
 *
 * /checkout, /billing-portal and /license all call Stripe. They are pointed at
 * a local mock via STRIPE_API_BASE so the success paths are genuinely
 * exercised — previously only their validation branches were reachable without
 * live Stripe credentials.
 */

import { req, json } from '../lib/harness.mjs';

const jsonPost = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

export async function run(r, worker) {
  r.suite('Billing Worker (workers/billing)');
  const base = worker.base;

  // --- CORS preflight ---
  const opt = await req(base, '/checkout', { method: 'OPTIONS' });
  r.status('billing.options', 'OPTIONS preflight returns 200', opt, 200);

  // --- /checkout validation ---
  r.status('billing.checkout.bad-json', 'malformed JSON rejected',
    await req(base, '/checkout', jsonPost('{oops')), 400);
  r.status('billing.checkout.unknown-plan', 'unknown plan rejected',
    await req(base, '/checkout', jsonPost({ plan: 'enterprise_gold', email: 'a@b.com' })), 400);
  r.status('billing.checkout.bad-email', 'malformed e-mail rejected',
    await req(base, '/checkout', jsonPost({ plan: 'pro_per_repo', email: 'nope' })), 400);

  // --- /checkout happy path, through the Stripe mock ---
  const co = await req(base, '/checkout', jsonPost({
    plan: 'pro_per_repo', email: 'buyer@preston-check.com', org_name: 'QG Org',
  }));
  r.status('billing.checkout.ok', 'valid checkout creates a session', co, 200);
  const coBody = await json(co);
  r.contains('billing.checkout.ok', 'returns a Stripe checkout URL',
    (coBody && coBody.url) || '', 'checkout.stripe.com');

  // --- /checkout rate limit: 5 per hour, so the 6th must be refused ---
  const rlEmail = 'rl-checkout@preston-check.com';
  let last = 0;
  for (let i = 0; i < 6; i++) {
    const resp = await req(base, '/checkout', jsonPost({ plan: 'pro_per_repo', email: rlEmail }));
    last = resp.status;
  }
  r.equal('billing.checkout.ratelimit', '6th checkout within the hour is 429', last, 429);

  // --- /billing-portal ---
  r.status('billing.billing-portal.bad-json', 'malformed JSON rejected',
    await req(base, '/billing-portal', jsonPost('{oops')), 400);
  r.status('billing.billing-portal.bad-email', 'malformed e-mail rejected',
    await req(base, '/billing-portal', jsonPost({ email: 'nope' })), 400);
  r.status('billing.billing-portal.no-cust', 'unknown customer is 404',
    await req(base, '/billing-portal', jsonPost({ email: 'ghost@preston-check.com' })), 404);

  // Seed a customer so the portal success path is reachable.
  worker.query(
    "INSERT INTO customers (email, stripe_customer_id) VALUES ('portal@preston-check.com', 'cus_QGtest123456')"
  );
  const bp = await req(base, '/billing-portal', jsonPost({ email: 'portal@preston-check.com' }));
  r.status('billing.billing-portal.ok', 'known customer gets a portal URL', bp, 200);
  const bpBody = await json(bp);
  r.contains('billing.billing-portal.ok', 'returns a Stripe billing-portal URL',
    (bpBody && bpBody.url) || '', 'billing.stripe.com');

  // --- /license ---
  r.status('billing.license.bad-json', 'malformed JSON rejected',
    await req(base, '/license', jsonPost('{oops')), 400);
  r.status('billing.license.bad-session-id', 'non cs_ session id rejected',
    await req(base, '/license', jsonPost({ session_id: 'evil' })), 400);
  r.status('billing.license.incomplete', 'incomplete checkout yields no license',
    await req(base, '/license', jsonPost({ session_id: 'cs_test_incomplete' })), 400);

  // --- unknown route ---
  r.status('billing.notfound', 'unknown path is 404',
    await req(base, '/nope', { method: 'GET' }), 404);
}
