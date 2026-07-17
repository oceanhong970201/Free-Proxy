-- Apply once to the existing remote D1 database before deploying the atomic
-- snapshot Worker. Fresh databases should use infra/d1/schema.sql instead.

ALTER TABLE nodes ADD COLUMN snapshot_id TEXT;

CREATE INDEX IF NOT EXISTS idx_nodes_snapshot ON nodes(snapshot_id, alive);
CREATE INDEX IF NOT EXISTS idx_nodes_alive_quality
  ON nodes(alive, download_speed DESC, latency_ms ASC);

CREATE TABLE IF NOT EXISTS import_state(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  snapshot_id TEXT NOT NULL,
  expected_count INTEGER NOT NULL,
  imported_count INTEGER NOT NULL,
  completed_at INTEGER NOT NULL
);
