-- Preston-Check telemetry D1 schema
-- Apply with: wrangler d1 execute preston-check-telemetry --file=schema.sql

CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_hash   TEXT NOT NULL,           -- SHA-256 of remote origin URL
  version     TEXT NOT NULL,           -- Preston-Check release version
  tier        TEXT NOT NULL,           -- free | pro | enterprise
  lang        TEXT NOT NULL,           -- primary detected language
  pass        INTEGER NOT NULL,
  fail        INTEGER NOT NULL,
  warn        INTEGER NOT NULL,
  skip        INTEGER NOT NULL,
  total       INTEGER NOT NULL,
  score       INTEGER NOT NULL,        -- pass*100/total
  timestamp   TEXT NOT NULL,           -- ISO 8601 UTC
  inserted_at INTEGER DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_repo_hash ON scans(repo_hash);
CREATE INDEX IF NOT EXISTS idx_scans_lang_timestamp ON scans(lang, timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_tier ON scans(tier);
CREATE INDEX IF NOT EXISTS idx_scans_inserted_at ON scans(inserted_at);

-- 90-day TTL for raw records (aggregate KV stays forever)
-- Run nightly via Cloudflare Worker cron:
--   DELETE FROM scans WHERE inserted_at < strftime('%s','now') - 86400 * 90;
