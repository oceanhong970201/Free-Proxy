-- Apply after 0002_atomic_snapshots.sql on databases created from the
-- original schema.  node_json remains authoritative; these columns make the
-- complete connection model queryable without decoding JSON.

ALTER TABLE nodes ADD COLUMN method TEXT;
ALTER TABLE nodes ADD COLUMN security TEXT;
ALTER TABLE nodes ADD COLUMN tls INTEGER;
ALTER TABLE nodes ADD COLUMN path TEXT;
ALTER TABLE nodes ADD COLUMN host_header TEXT;
ALTER TABLE nodes ADD COLUMN flow TEXT;
ALTER TABLE nodes ADD COLUMN packet_encoding TEXT;
ALTER TABLE nodes ADD COLUMN fp TEXT;
ALTER TABLE nodes ADD COLUMN alpn TEXT;
ALTER TABLE nodes ADD COLUMN pbk TEXT;
ALTER TABLE nodes ADD COLUMN sid TEXT;
ALTER TABLE nodes ADD COLUMN spider_x TEXT;
ALTER TABLE nodes ADD COLUMN utls INTEGER;
ALTER TABLE nodes ADD COLUMN skip_cert_verify INTEGER;
ALTER TABLE nodes ADD COLUMN alter_id INTEGER;
ALTER TABLE nodes ADD COLUMN transport_mode TEXT;
ALTER TABLE nodes ADD COLUMN protocol TEXT;
ALTER TABLE nodes ADD COLUMN protocol_param TEXT;
ALTER TABLE nodes ADD COLUMN obfs TEXT;
ALTER TABLE nodes ADD COLUMN obfs_param TEXT;
ALTER TABLE nodes ADD COLUMN congestion_control TEXT;
ALTER TABLE nodes ADD COLUMN udp_relay_mode TEXT;
ALTER TABLE nodes ADD COLUMN node_json TEXT;
