/**
 * Stripe webhook acceptance suite.
 *
 * Drives every event type the Worker dispatches on, each with a real
 * HMAC-SHA256 signature built the way Stripe builds it. The event list is
 * taken from surface.json and cross-checked against the Worker source by
 * drift-check, so a newly handled event type cannot slip through untested.
 *
 * Signature rejection is tested before anything else: a webhook endpoint that
 * accepts unsigned payloads is a remote write primitive on billing state.
 */

import { req, json } from '../lib/harness.mjs';
import { signPayload, makeEvent, objectFor, WEBHOOK_SECRET } from '../lib/stripe.mjs';

const post = (payload, sig) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
  body: payload,
});

export async function run(r, worker, events) {
  r.suite('Stripe webhook (workers/billing /webhook)');
  const base = worker.base;

  // --- signature enforcement ---
  const goodPayload = JSON.stringify(makeEvent('invoice.paid', objectFor('invoice.paid')));

  r.status('billing.webhook.bad-signature', 'missing signature header rejected',
    await req(base, '/webhook', post(goodPayload, '')), 400);
  r.status('billing.webhook.bad-signature', 'garbage signature rejected',
    await req(base, '/webhook', post(goodPayload, 't=1,v1=deadbeef')), 400);
  r.status('billing.webhook.bad-signature', 'signature from the wrong secret rejected',
    await req(base, '/webhook', post(goodPayload, signPayload(goodPayload, 'whsec_wrong_secret'))), 400);

  // A correctly signed but non-JSON body must fail parsing, not signature.
  const notJson = 'this is not json';
  r.status('billing.webhook.bad-json', 'validly signed non-JSON body rejected',
    await req(base, '/webhook', post(notJson, signPayload(notJson))), 400);

  // --- every dispatched event type ---
  const sentIds = [];
  for (const { id, type } of events) {
    const event = makeEvent(type, objectFor(type));
    const payload = JSON.stringify(event);
    const resp = await req(base, '/webhook', post(payload, signPayload(payload)));
    const ok = r.status(id, `${type} accepted`, resp, 200);
    if (ok) sentIds.push(event.id);

    // The event must be recorded, which is what makes replay detection work.
    const rows = worker.query(
      `SELECT type FROM webhook_events WHERE stripe_event_id='${event.id}'`
    );
    r.truthy(id, `${type} persisted to webhook_events`,
      rows.length === 1 && rows[0].type === type,
      `expected 1 row of type ${type}, got ${JSON.stringify(rows)}`);
  }

  // --- idempotency / replay ---
  // Stripe retries deliveries; the same event id must not be applied twice.
  const dupEvent = makeEvent('invoice.paid', objectFor('invoice.paid'));
  const dupPayload = JSON.stringify(dupEvent);
  const first = await req(base, '/webhook', post(dupPayload, signPayload(dupPayload)));
  const second = await req(base, '/webhook', post(dupPayload, signPayload(dupPayload)));

  r.status('billing.webhook.duplicate', 'first delivery accepted', first, 200);
  r.status('billing.webhook.duplicate', 'replayed delivery still 200', second, 200);
  const secondBody = await json(second);
  r.equal('billing.webhook.duplicate', 'replay reported as duplicate',
    secondBody && secondBody.duplicate, true);

  const dupRows = worker.query(
    `SELECT COUNT(*) AS n FROM webhook_events WHERE stripe_event_id='${dupEvent.id}'`
  );
  r.equal('billing.webhook.duplicate', 'replay stored exactly once',
    Number(dupRows[0] && dupRows[0].n), 1);
}
