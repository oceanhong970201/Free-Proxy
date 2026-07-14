-- D1 schema for proxy-sub-aggregator
-- Shared between local SQLite (nodes.db) and Cloudflare D1 (nodes-db).
-- Apply on D1 after `wrangler d1 create nodes-db`:
--   npx wrangler d1 execute nodes-db --file=infra/d1/schema.sql

CREATE TABLE IF NOT EXISTS nodes(
  id INTEGER PRIMARY KEY,
  uri TEXT NOT NULL UNIQUE,
  proto TEXT, host TEXT, port INTEGER,
  uuid TEXT, password TEXT, sni TEXT, net TEXT,
  country TEXT, latency_ms INTEGER, download_speed REAL, alive INTEGER,
  source TEXT, first_seen INTEGER, last_checked INTEGER,
  content_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_alive ON nodes(alive, latency_ms);
CREATE INDEX IF NOT EXISTS idx_proto ON nodes(proto);

CREATE TABLE IF NOT EXISTS sources(
  id TEXT PRIMARY KEY, url TEXT, format TEXT,
  enabled INTEGER, tier INTEGER, last_fetch INTEGER, last_count INTEGER, status TEXT
);
