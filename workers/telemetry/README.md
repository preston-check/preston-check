# Preston-Check Telemetry Endpoint

Cloudflare Worker that receives opt-in anonymous telemetry from `preston-check --telemetry-opt-in` runs and powers two moats:

1. **The annual State of Fintech Security report** — aggregated trends across thousands of fintech codebases, becoming the canonical industry benchmark.
2. **Peer-comparison percentiles in the SaaS dashboard** — "your fintech scores in the 67th percentile for cryptography hygiene among US payment processors" requires this dataset.

## Privacy contract

The endpoint accepts only the documented schema fields. It rejects anything else. It never receives:

- Source code or file content
- File paths or file names
- Specific check IDs that failed
- Customer details
- IP addresses (stripped after rate-limiting)

What it does receive: tool version, license tier, primary language, SHA-256 hash of git remote origin URL (so the same repo dedupes without being identifiable), aggregate counts, UTC timestamp.

The full validation logic is in `src/index.ts`. The contract is the same as the in-scanner telemetry function in `lib/telemetry.sh` — they are designed to be auditable in the open repo together.

## Deploy

```bash
cd workers/telemetry/
npm install -g wrangler
wrangler login

# Create D1 database and KV namespace, paste IDs into wrangler.toml
wrangler d1 create preston-check-telemetry
wrangler kv:namespace create AGGREGATE

# Apply schema
wrangler d1 execute preston-check-telemetry --file=schema.sql

# Deploy
wrangler deploy

# Bind to custom domain
# (Cloudflare dashboard → Workers → preston-check-telemetry → Triggers → Add custom domain)
# Pattern: preston-check.com/api/v1/telemetry
```

## Cron job for 90-day cleanup

Add to `wrangler.toml`:

```toml
[triggers]
crons = ["0 3 * * *"]   # 3am UTC daily
```

And in `src/index.ts` add a `scheduled` handler:

```typescript
async scheduled(event: ScheduledEvent, env: Env) {
  await env.DB.prepare(
    "DELETE FROM scans WHERE inserted_at < strftime('%s','now') - 86400 * 90"
  ).run();
}
```

## Aggregations powered by the KV layer

The KV namespace stores rolling counters that the SaaS dashboard reads in real-time without hitting D1. Keys:

- `agg:day:{YYYY-MM-DD}:scans` — total scans that day
- `agg:day:{YYYY-MM-DD}:tier:{free|pro|enterprise}` — by tier
- `agg:day:{YYYY-MM-DD}:lang:{java|...}` — by language
- `agg:lang:{lang}:scans` — cumulative by language
- `agg:tier:{tier}:scans` — cumulative by tier
- `hist:lang:{lang}:score:{bucket}` — histogram for percentile computation

The dashboard exposes these as `https://preston-check.com/api/v1/stats/{key}` for the live "scans this week" counter and the percentile-comparison widget.

## Cost

Cloudflare Workers free tier: 100k requests/day, 10ms CPU per request. Free until ~3M scans/month.

D1 free tier: 5M reads/day, 100k writes/day. Free until ~3k scans/day sustained.

KV free tier: 100k reads/day, 1k writes/day. Sufficient for aggregations alone (each scan triggers ~5 writes).

Estimated cost at 100k scans/day: ~$5/month. At 1M scans/day: ~$50/month.
