-- Preston-Check auth D1 schema
--
-- Two tables: accounts (one row per email-verified org owner) and
-- sessions (one row per active browser session, max one per account).
-- Short-lived 6-digit verification codes live in KV with a 10-min TTL,
-- not in D1.

CREATE TABLE IF NOT EXISTS accounts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  org_name      TEXT,
  created_at    INTEGER DEFAULT (strftime('%s','now')),
  last_login_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,            -- 32-byte hex random
  account_id  INTEGER NOT NULL,
  email       TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER DEFAULT (strftime('%s','now')),
  user_agent  TEXT,
  ip_hash     TEXT,                         -- SHA-256 hash, never raw IP
  FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
