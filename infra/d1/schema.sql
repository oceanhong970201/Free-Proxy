-- D1 schema for proxy-sub-aggregator
-- Shared between local SQLite (nodes.db) and Cloudflare D1 (nodes-db).
-- From src/worker, apply to a fresh remote D1 after creating the database:
--   npx wrangler d1 execute nodes-db --remote --file=../../infra/d1/schema.sql

CREATE TABLE IF NOT EXISTS nodes(
  id INTEGER PRIMARY KEY,
  uri TEXT NOT NULL UNIQUE,
  proto TEXT, host TEXT, port INTEGER,
  uuid TEXT, alter_id INTEGER, password TEXT, method TEXT, sni TEXT, net TEXT,
  transport_mode TEXT,
  security TEXT, tls INTEGER, path TEXT, host_header TEXT, flow TEXT,
  packet_encoding TEXT, fp TEXT, alpn TEXT, pbk TEXT, sid TEXT,
  spider_x TEXT, utls INTEGER,
  skip_cert_verify INTEGER, protocol TEXT, protocol_param TEXT,
  obfs TEXT, obfs_param TEXT, congestion_control TEXT, udp_relay_mode TEXT,
  country TEXT, latency_ms INTEGER, download_speed REAL, alive INTEGER,
  source TEXT, first_seen INTEGER, last_checked INTEGER,
  content_hash TEXT, node_json TEXT, snapshot_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_alive ON nodes(alive, latency_ms);
CREATE INDEX IF NOT EXISTS idx_proto ON nodes(proto);
CREATE INDEX IF NOT EXISTS idx_nodes_snapshot ON nodes(snapshot_id, alive);
CREATE INDEX IF NOT EXISTS idx_nodes_alive_quality
  ON nodes(alive, download_speed DESC, latency_ms ASC);

CREATE TABLE IF NOT EXISTS sources(
  id TEXT PRIMARY KEY, url TEXT, format TEXT,
  enabled INTEGER, tier INTEGER, last_fetch INTEGER, last_count INTEGER, status TEXT
);

CREATE TABLE IF NOT EXISTS import_state(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  snapshot_id TEXT NOT NULL,
  expected_count INTEGER NOT NULL,
  imported_count INTEGER NOT NULL,
  completed_at INTEGER NOT NULL
);
