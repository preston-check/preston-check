# Telemetry — Opt-In Anonymous Scoring

## TL;DR

Preston-Check telemetry is **off by default**. When you opt in, exactly one
HTTP POST per scan is sent. The payload contains aggregate counts and a
salted hash of your repo URL. **No source code, file paths, file names, or
specific check names are ever transmitted.**

## What gets sent

```json
{
  "version":   "1.7.1",
  "tier":      "free",
  "lang":      "typescript",
  "repo_hash": "sha256(remote.origin.url)",
  "pass":      120,
  "fail":      7,
  "warn":      14,
  "skip":      5,
  "total":     146,
  "timestamp": "2026-05-03T19:42:27Z"
}
```

That is the entire payload. It maps to `workers/telemetry/src/index.ts` on
the server, which validates the schema and stores aggregates in Cloudflare
KV (90-day TTL on raw records).

## What is **never** sent

* Any source code content.
* File paths or file names.
* Specific check IDs that failed.
* Customer names, emails, or PII of any kind.
* Network addresses (the server sees your IP at the TCP layer; we strip it
  before storage).

The privacy promise is enforceable by reading `lib/telemetry.sh` —
the function is fewer than 30 lines on purpose.

## Why we ask

The data moat is the only Preston-Check asset competitors literally cannot
copy. It powers the annual State of Fintech Security report, the
peer-comparison feature in the dashboard, and the LLM training data that
gets the false-positive filter sharper over time. Telemetry-emitting
customers are the foundation of all of that — once a few hundred scans
flow through, the dataset starts producing benchmarks no one else has.

## How to opt in

There are three equivalent ways. Pick whichever fits your workflow.

### Per-run flag

```bash
preston-check --telemetry-opt-in
```

### Environment variable (good for CI)

```bash
export PRESTON_TELEMETRY=1
preston-check
```

### Config file

```yaml
# config.yml
telemetry: opt_in
```

### Make it the default for your shell

```bash
echo 'export PRESTON_TELEMETRY=1' >> ~/.zshrc   # or ~/.bashrc
```

After that, every Preston-Check scan from your machine reports an
anonymous score. You can disable it for a specific scan with `--airgap`,
which forbids all network calls and forces telemetry off regardless of
config or env.

## How to verify what gets sent

```bash
# Dry-run with verbose curl tracing — shows the exact payload, then aborts.
PRESTON_TELEMETRY=1 \
  PRESTON_TELEMETRY_ENDPOINT="https://httpbin.org/post" \
  preston-check --light
```

The endpoint override redirects the POST to a public echo service so you
can confirm the payload visually before pointing at the real endpoint.

## Custom endpoint (Enterprise)

Enterprise customers can self-host the telemetry collector. The full
schema and a deploy-ready Cloudflare Worker live in
[`workers/telemetry/`](../workers/telemetry/README.md). Point the runner
at your own collector with:

```bash
export PRESTON_TELEMETRY_ENDPOINT="https://telemetry.acme.internal/v1/ingest"
```

This is also the path for air-gapped fintechs that want internal
benchmarking without sending data to preston-check.com.

## Opting back out

Either remove the flag/env var/config, or set `--airgap`. There is no
delete request endpoint because the server stores no PII to delete — the
only identifier is the salted repo-URL hash, which the server cannot
reverse without the original URL string.
