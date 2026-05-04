-- Preston-Check billing D1 schema
--
-- Mirrors the subset of Stripe state we need to render the customer
-- portal's billing surface and the admin portal's revenue dashboard.
-- Stripe is the source of truth; D1 is a denormalized cache populated
-- by the webhook handler so the portal can render without round-
-- tripping to Stripe on every request.

-- Customers — one row per Stripe Customer object.
-- Email is the join key with our own user records (later, when auth
-- lands) and with Stripe.
CREATE TABLE IF NOT EXISTS customers (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_customer_id   TEXT NOT NULL UNIQUE,
  email                TEXT NOT NULL,
  org_name             TEXT,
  created_at           INTEGER DEFAULT (strftime('%s','now')),
  updated_at           INTEGER DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);

-- Subscriptions — one row per Stripe Subscription object.
-- Status follows Stripe's enum: trialing, active, past_due, canceled,
-- unpaid, incomplete, incomplete_expired, paused.
CREATE TABLE IF NOT EXISTS subscriptions (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_subscription_id   TEXT NOT NULL UNIQUE,
  stripe_customer_id       TEXT NOT NULL,
  status                   TEXT NOT NULL,
  plan                     TEXT NOT NULL,         -- 'pro_per_repo' | 'pro_unlimited' | 'enterprise'
  current_period_start     INTEGER,
  current_period_end       INTEGER,
  cancel_at_period_end     INTEGER DEFAULT 0,
  created_at               INTEGER DEFAULT (strftime('%s','now')),
  updated_at               INTEGER DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status   ON subscriptions(status);

-- Invoices — one row per Stripe Invoice object.
-- amount_paid is in cents (Stripe convention); divide by 100 for dollars.
CREATE TABLE IF NOT EXISTS invoices (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_invoice_id        TEXT NOT NULL UNIQUE,
  stripe_customer_id       TEXT NOT NULL,
  stripe_subscription_id   TEXT,
  status                   TEXT NOT NULL,         -- 'draft' | 'open' | 'paid' | 'void' | 'uncollectible'
  amount_due               INTEGER NOT NULL,
  amount_paid              INTEGER DEFAULT 0,
  currency                 TEXT DEFAULT 'usd',
  hosted_invoice_url       TEXT,
  invoice_pdf              TEXT,
  paid_at                  INTEGER,
  created_at               INTEGER DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_invoices_customer ON invoices(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status   ON invoices(status);

-- Webhook events — append-only log of every Stripe event we received.
-- Used for replay during incidents and for debugging. Idempotency check:
-- before processing an event, verify the stripe_event_id isn't already
-- present here (Stripe may deliver the same event multiple times).
CREATE TABLE IF NOT EXISTS webhook_events (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_event_id      TEXT NOT NULL UNIQUE,
  type                 TEXT NOT NULL,
  livemode             INTEGER NOT NULL,
  payload              TEXT NOT NULL,
  processed_at         INTEGER DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_webhook_events_type ON webhook_events(type);
