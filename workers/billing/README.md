# Preston-Check Billing Worker

Cloudflare Worker that handles Stripe Checkout creation and webhook
event ingestion. Mirrors subscription + invoice state into D1 so the
customer portal can render billing information without round-tripping
to Stripe on every request.

## URLs

- POST `https://preston-check-billing.preston-check-edge.workers.dev/checkout`
- POST `https://preston-check-billing.preston-check-edge.workers.dev/webhook`

## Bindings

| Name | Type | Value / Source |
|---|---|---|
| `DB` | D1 | preston-check-billing (`abeeb20d-935f-4551-8d2e-a8eaecee8c0b`) |
| `STATE` | KV | BILLING_STATE (`500f3cf24df84395a0ce62478abedfc9`) |
| `ALLOW_ORIGIN` | env | `https://app.preston-check.com` |
| `SUCCESS_URL` | env | `https://app.preston-check.com/#/settings` |
| `CANCEL_URL` | env | `https://app.preston-check.com/#/settings` |

## Secrets

Set via `wrangler secret put <NAME>` — never committed.

| Name | Source |
|---|---|
| `STRIPE_SECRET_KEY` | Stripe dashboard → Developers → API keys → Secret key (`sk_live_...` or `sk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | Stripe dashboard → Developers → Webhooks → click the endpoint → Signing secret (`whsec_...`) |
| `STRIPE_PRICE_PRO_PER_REPO` | Price ID for the $999/repo/yr Pro plan (`price_...`) |
| `STRIPE_PRICE_PRO_UNLIMITED` | Price ID for the $4,999/yr unlimited Pro plan (`price_...`) |

## One-time setup

```bash
# 1. Apply schema
wrangler d1 execute preston-check-billing --remote --file=workers/billing/schema.sql

# 2. Set secrets (one-time)
wrangler secret put STRIPE_SECRET_KEY            # paste sk_live_... or sk_test_...
wrangler secret put STRIPE_WEBHOOK_SECRET        # paste whsec_...
wrangler secret put STRIPE_PRICE_PRO_PER_REPO    # paste price_...
wrangler secret put STRIPE_PRICE_PRO_UNLIMITED   # paste price_...

# 3. Deploy
cd workers/billing
wrangler deploy
```

## Stripe dashboard configuration

Two products + four prices, set up once in the Stripe dashboard:

| Product | Price | ID env var | Description |
|---|---|---|---|
| Preston-Check Pro | $999 / yr | `STRIPE_PRICE_PRO_PER_REPO` | Billed per repository |
| Preston-Check Pro | $4,999 / yr | `STRIPE_PRICE_PRO_UNLIMITED` | Unlimited repositories |

Webhook endpoint: `https://preston-check-billing.preston-check-edge.workers.dev/webhook`

Events to subscribe to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.paid`
- `invoice.payment_failed`
- `invoice.finalized`

After creating the webhook, Stripe shows a "Signing secret" (`whsec_...`)
on the endpoint detail page. That's what goes into `STRIPE_WEBHOOK_SECRET`.

## Test the integration

```bash
# Smoke test the checkout endpoint (requires the worker to be deployed
# and STRIPE_SECRET_KEY + STRIPE_PRICE_PRO_UNLIMITED to be set).
curl -X POST 'https://preston-check-billing.preston-check-edge.workers.dev/checkout' \
  -H 'Content-Type: application/json' \
  -d '{"plan": "pro_unlimited", "email": "test@example.com"}'

# Expected response: {"url": "https://checkout.stripe.com/...", "id": "cs_test_..."}
# Open the URL in a browser to walk through Stripe Checkout. Use Stripe's
# test card 4242 4242 4242 4242 (any future expiry, any CVC, any zip).
```

## Live vs test mode

Same code, swap secrets:

| Env var | Test mode | Live mode |
|---|---|---|
| `STRIPE_SECRET_KEY` | `sk_test_...` | `sk_live_...` |
| `STRIPE_WEBHOOK_SECRET` | from Test webhook endpoint | from Live webhook endpoint |
| `STRIPE_PRICE_PRO_PER_REPO` | test-mode price | live-mode price |
| `STRIPE_PRICE_PRO_UNLIMITED` | test-mode price | live-mode price |

Test mode and live mode have *separate* products + prices in Stripe.
You can't reuse a `price_test_...` ID with a `sk_live_...` key.

## Rate limits

- Checkout creation is rate-limited to **5 sessions per hour per email**.
  Stored in the KV namespace with a 1h TTL. Prevents abuse and accidental
  spam from a UI loop.
- Webhook ingestion has no rate limit by design — Stripe will retry on
  failure, and we want to accept their retries.

## Querying state

```bash
# Subscription summary
wrangler d1 execute preston-check-billing --remote --command \
  "SELECT plan, status, count(*) FROM subscriptions GROUP BY plan, status"

# This month's invoices
wrangler d1 execute preston-check-billing --remote --command \
  "SELECT status, count(*), sum(amount_paid)/100.0 AS dollars FROM invoices
   WHERE created_at > strftime('%s','now','start of month') GROUP BY status"
```

## Known limits

- The Worker doesn't currently persist `customer_email` ↔ `org_name` if
  the customer signed up before going through Checkout. Once the
  customer portal has real auth (Q3 2026), the email-on-account becomes
  authoritative and we drop the metadata field reliance.
- Tax handling is enabled (`tax_id_collection`) but Stripe Tax must be
  configured in the dashboard for actual tax calculation.
- Subscription cancellation flow goes through the Stripe Customer
  Portal (not implemented here yet — the customer portal Settings tab
  will add a "Manage subscription" button that redirects to Stripe's
  hosted portal).
