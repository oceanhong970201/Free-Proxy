import { decodeBase64Utf8, encodeBase64Utf8, renderClashYaml, uriToClashProxy } from "./subscription";

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ADMIN_TOKEN: string;
  HEALTH_MAX_AGE_SECONDS?: string;
}

interface SnapshotNodeInput {
  uri: string;
  alive?: boolean;
  latency_ms?: number | null;
  download_speed?: number | null;
  model?: Record<string, unknown> | null;
}

interface SnapshotImport {
  version: 1;
  snapshotId: string;
  expectedCount: number;
  nodes: SnapshotNodeInput[];
  legacy: boolean;
}

interface ImportStateRow {
  snapshot_id: string;
  expected_count: number;
  imported_count: number;
  completed_at: number;
}

interface HealthSnapshotRow extends ImportStateRow {
  total_nodes: number;
  alive_nodes: number;
  snapshot_nodes: number;
}

const CACHE_KEY_PREFIXES = {
  base64: "sub-render-v3",
  clash: "sub-render-clash-v3",
} as const;
const LEGACY_CACHE_KEYS = ["sub-render", "sub-render-clash", "sub-render-v2", "sub-render-clash-v2"];
const CACHE_TTL_SECONDS = 60;
const MAX_SNAPSHOT_READ_ATTEMPTS = 3;
const DEFAULT_HEALTH_MAX_AGE_SECONDS = 8 * 60 * 60;
// The publisher intentionally caps snapshots at 100 nodes.  Keeping the same
// boundary here also places a predictable upper bound on the JSON1 upsert
// payload and on subscription rendering work.
const MAX_IMPORT_NODES = 100;
const MAX_IMPORT_BODY_BYTES = 1024 * 1024;
const MAX_URI_LENGTH = 16_384;

// One set-based statement persists every incoming node.  In particular, do
// not turn this back into one D1 statement per node: a normal 100-node publish
// would then exceed D1's batch/query limits once stale-node and state updates
// are included.  json_each keeps the atomic batch at exactly three statements.
const UPSERT_SNAPSHOT_SQL = `
  WITH incoming(value) AS (SELECT value FROM json_each(?))
  INSERT INTO nodes (
    uri, proto, host, port, uuid, alter_id, password, method, sni, net,
    transport_mode, security, tls, path, host_header, flow, packet_encoding,
    fp, alpn, pbk, sid, spider_x, utls, skip_cert_verify, protocol,
    protocol_param, obfs, obfs_param, congestion_control, udp_relay_mode,
    country, source, node_json, alive, latency_ms, download_speed,
    first_seen, last_checked, content_hash, snapshot_id
  )
  SELECT
    json_extract(value, '$.uri'),
    COALESCE(json_extract(value, '$.model.proto'), json_extract(value, '$.fallback.proto')),
    COALESCE(json_extract(value, '$.model.host'), json_extract(value, '$.fallback.host')),
    COALESCE(json_extract(value, '$.model.port'), json_extract(value, '$.fallback.port')),
    json_extract(value, '$.model.uuid'),
    json_extract(value, '$.model.alter_id'),
    json_extract(value, '$.model.password'),
    json_extract(value, '$.model.method'),
    json_extract(value, '$.model.sni'),
    json_extract(value, '$.model.net'),
    json_extract(value, '$.model.transport_mode'),
    json_extract(value, '$.model.security'),
    json_extract(value, '$.model.tls'),
    json_extract(value, '$.model.path'),
    json_extract(value, '$.model.host_header'),
    json_extract(value, '$.model.flow'),
    json_extract(value, '$.model.packet_encoding'),
    json_extract(value, '$.model.fp'),
    json_extract(value, '$.model.alpn'),
    json_extract(value, '$.model.pbk'),
    json_extract(value, '$.model.sid'),
    json_extract(value, '$.model.spider_x'),
    json_extract(value, '$.model.utls'),
    json_extract(value, '$.model.skip_cert_verify'),
    json_extract(value, '$.model.protocol'),
    json_extract(value, '$.model.protocol_param'),
    json_extract(value, '$.model.obfs'),
    json_extract(value, '$.model.obfs_param'),
    json_extract(value, '$.model.congestion_control'),
    json_extract(value, '$.model.udp_relay_mode'),
    json_extract(value, '$.model.country'),
    json_extract(value, '$.model.source'),
    json_extract(value, '$.model'),
    1,
    json_extract(value, '$.latency_ms'),
    json_extract(value, '$.download_speed'),
    ?,
    ?,
    json_extract(value, '$.content_hash'),
    ?
  FROM incoming
  WHERE true
  ON CONFLICT(uri) DO UPDATE SET
    proto = excluded.proto,
    host = excluded.host,
    port = excluded.port,
    uuid = excluded.uuid,
    alter_id = excluded.alter_id,
    password = excluded.password,
    method = excluded.method,
    sni = excluded.sni,
    net = excluded.net,
    transport_mode = excluded.transport_mode,
    security = excluded.security,
    tls = excluded.tls,
    path = excluded.path,
    host_header = excluded.host_header,
    flow = excluded.flow,
    packet_encoding = excluded.packet_encoding,
    fp = excluded.fp,
    alpn = excluded.alpn,
    pbk = excluded.pbk,
    sid = excluded.sid,
    spider_x = excluded.spider_x,
    utls = excluded.utls,
    skip_cert_verify = excluded.skip_cert_verify,
    protocol = excluded.protocol,
    protocol_param = excluded.protocol_param,
    obfs = excluded.obfs,
    obfs_param = excluded.obfs_param,
    congestion_control = excluded.congestion_control,
    udp_relay_mode = excluded.udp_relay_mode,
    country = excluded.country,
    source = excluded.source,
    node_json = excluded.node_json,
    alive = 1,
    latency_ms = COALESCE(excluded.latency_ms, nodes.latency_ms),
    download_speed = COALESCE(excluded.download_speed, nodes.download_speed),
    last_checked = excluded.last_checked,
    content_hash = excluded.content_hash,
    snapshot_id = excluded.snapshot_id`;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (pathname === "/health" && request.method === "GET") return handleHealth(env);
    if (pathname === "/sub" && request.method === "GET") return handleSub(request, env, ctx);
    if (pathname === "/admin/import" && request.method === "POST") return handleImport(request, env);
    return new Response("Not Found", { status: 404 });
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await env.DB.prepare("SELECT 1").first();
  },
};

export async function handleSub(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const format = (new URL(request.url).searchParams.get("format") || "").toLowerCase();
  const clash = format === "clash";
  for (let attempt = 0; attempt < MAX_SNAPSHOT_READ_ATTEMPTS; attempt += 1) {
    const before = await readRenderState(env.DB);
    if (before && !isCompleteRenderState(before)) continue;
    const cacheKey = renderCacheKey(clash, before);
    const cached = await env.CACHE.get(cacheKey, "text");
    if (cached !== null) {
      const afterCache = await readRenderState(env.DB);
      if (!sameRenderState(before, afterCache)) continue;
      return clash ? clashResponse(cached) : subResponse(cached);
    }

    const statement = before
      ? env.DB.prepare(
        `SELECT uri FROM nodes
         WHERE alive = 1 AND snapshot_id = ?
         ORDER BY COALESCE(download_speed, -1) DESC,
                  COALESCE(latency_ms, 999999) ASC,
                  uri ASC`
      ).bind(before.snapshot_id)
      : env.DB.prepare(
        `SELECT uri FROM nodes
         WHERE alive = 1 AND snapshot_id IS NULL
         ORDER BY COALESCE(download_speed, -1) DESC,
                  COALESCE(latency_ms, 999999) ASC,
                  uri ASC`
      );
    const { results } = await statement.all<{ uri: string }>();
    const uris = (results || []).map((row) => row.uri).filter(Boolean);
    const afterQuery = await readRenderState(env.DB);
    if (!sameRenderState(before, afterQuery)) continue;
    if (before && uris.length !== Number(before.expected_count)) continue;

    let body: string;
    try {
      body = clash ? renderClashYaml(uris) : encodeBase64Utf8(uris.join("\n"));
    } catch {
      return renderUnavailableResponse(clash);
    }
    const afterRender = await readRenderState(env.DB);
    if (!sameRenderState(before, afterRender)) continue;
    ctx.waitUntil(env.CACHE.put(cacheKey, body, { expirationTtl: CACHE_TTL_SECONDS }));
    return clash ? clashResponse(body) : subResponse(body);
  }
  return renderUnavailableResponse(clash);
}

export async function handleImport(request: Request, env: Env): Promise<Response> {
  const token = request.headers.get("X-Admin-Token");
  if (!token || token !== env.ADMIN_TOKEN) return jsonResponse({ ok: false, error: "unauthorized" }, 401);

  let snapshot: SnapshotImport;
  try {
    snapshot = await parseSnapshotRequest(request);
  } catch (error) {
    return jsonResponse({ ok: false, error: errorMessage(error) }, 400);
  }

  const now = Date.now();
  const parsed = snapshot.nodes.map((node) => ({ node, parsed: quickParse(node.uri) }));
  const hashes = await Promise.all(snapshot.nodes.map((node) => sha256(node.uri)));
  const incoming = parsed.map(({ node, parsed: uriParts }, index) => {
    const model = node.model || null;
    return {
      uri: node.uri,
      model,
      fallback: model ? null : uriParts,
      latency_ms: node.latency_ms ?? null,
      download_speed: node.download_speed ?? null,
      content_hash: model?.content_hash ?? hashes[index],
    };
  });
  const statements = [
    env.DB.prepare(UPSERT_SNAPSHOT_SQL).bind(JSON.stringify(incoming), now, now, snapshot.snapshotId),
  ];
  statements.push(
    env.DB.prepare(
      "UPDATE nodes SET alive = 0 WHERE alive = 1 AND (snapshot_id IS NULL OR snapshot_id <> ?)"
    ).bind(snapshot.snapshotId)
  );
  statements.push(
    env.DB.prepare(
      `INSERT INTO import_state (id, snapshot_id, expected_count, imported_count, completed_at)
       VALUES (1, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         snapshot_id = excluded.snapshot_id,
         expected_count = excluded.expected_count,
         imported_count = excluded.imported_count,
         completed_at = excluded.completed_at`
    ).bind(snapshot.snapshotId, snapshot.expectedCount, snapshot.expectedCount, now)
  );

  let batchResults: D1Result<unknown>[];
  try {
    // D1 batch executes in one transaction and rolls back every statement on failure.
    batchResults = await env.DB.batch(statements);
  } catch (error) {
    return jsonResponse({ ok: false, complete: false, error: `database batch failed: ${errorMessage(error)}` }, 500);
  }
  if (batchResults.length !== statements.length || batchResults.some((result) => !result.success)) {
    return jsonResponse({ ok: false, complete: false, error: "database returned a partial batch result" }, 500);
  }

  const staleResult = batchResults[1];
  const staleDisabled = Number(staleResult.meta?.changes || 0);
  const verification = await verifySnapshot(env.DB, snapshot.snapshotId, snapshot.expectedCount);
  if (!verification.complete) {
    return jsonResponse({
      ok: false,
      complete: false,
      error: "post-import snapshot verification failed",
      snapshot_id: snapshot.snapshotId,
      expected: snapshot.expectedCount,
      active: verification.active,
      current_snapshot: verification.currentSnapshot,
    }, 500);
  }

  // Versioned cache keys make old snapshot renders unreachable.  Only remove
  // fixed keys left by pre-versioned deployments; cleanup is best-effort and
  // must not turn an already committed snapshot into an apparent failure.
  await clearLegacyRenderCaches(env.CACHE);

  return jsonResponse({
    ok: true,
    complete: true,
    imported: snapshot.expectedCount,
    expected: snapshot.expectedCount,
    snapshot_id: snapshot.snapshotId,
    stale_disabled: staleDisabled,
    legacy: snapshot.legacy,
    model_persisted: !snapshot.legacy,
  });
}

async function readRenderState(db: D1Database): Promise<ImportStateRow | null> {
  return db.prepare(
    "SELECT snapshot_id, expected_count, imported_count, completed_at FROM import_state WHERE id = 1"
  ).first<ImportStateRow>();
}

function isCompleteRenderState(state: ImportStateRow): boolean {
  const expected = Number(state.expected_count);
  return Number.isInteger(expected) && expected > 0 && Number(state.imported_count) === expected;
}

function sameRenderState(left: ImportStateRow | null, right: ImportStateRow | null): boolean {
  if (!left || !right) return left === right;
  return left.snapshot_id === right.snapshot_id &&
    Number(left.expected_count) === Number(right.expected_count) &&
    Number(left.imported_count) === Number(right.imported_count) &&
    Number(left.completed_at) === Number(right.completed_at);
}

function renderCacheKey(clash: boolean, state: ImportStateRow | null): string {
  const prefix = clash ? CACHE_KEY_PREFIXES.clash : CACHE_KEY_PREFIXES.base64;
  if (!state) return `${prefix}:legacy`;
  return `${prefix}:${encodeURIComponent(state.snapshot_id)}:${Number(state.completed_at)}`;
}

async function clearLegacyRenderCaches(cache: KVNamespace): Promise<void> {
  await Promise.allSettled(LEGACY_CACHE_KEYS.map((key) => cache.delete(key)));
}

async function handleHealth(env: Env): Promise<Response> {
  const checkedAt = Date.now();
  const maxAgeSeconds = positiveInteger(env.HEALTH_MAX_AGE_SECONDS) || DEFAULT_HEALTH_MAX_AGE_SECONDS;
  // Keep state and counts in one SQLite read snapshot.  Separate concurrent
  // queries can otherwise describe different imports during a publish race.
  const healthSnapshotPromise = env.DB.prepare(
    `SELECT
       state.snapshot_id,
       state.expected_count,
       state.imported_count,
       state.completed_at,
       COUNT(nodes.id) AS total_nodes,
       COALESCE(SUM(CASE WHEN nodes.alive = 1 THEN 1 ELSE 0 END), 0) AS alive_nodes,
       COALESCE(SUM(CASE WHEN nodes.alive = 1 AND nodes.snapshot_id = state.snapshot_id
         THEN 1 ELSE 0 END), 0) AS snapshot_nodes
     FROM import_state AS state
     LEFT JOIN nodes ON true
     WHERE state.id = 1
     GROUP BY state.id, state.snapshot_id, state.expected_count,
              state.imported_count, state.completed_at`
  ).first<HealthSnapshotRow>();
  const [snapshotResult, kvResult] = await Promise.allSettled([
    healthSnapshotPromise,
    env.CACHE.get("__health_probe__"),
  ]);

  const dbOk = snapshotResult.status === "fulfilled";
  const kvOk = kvResult.status === "fulfilled";
  const state = snapshotResult.status === "fulfilled" ? snapshotResult.value : null;
  const ageSeconds = state ? Math.floor((checkedAt - Number(state.completed_at)) / 1000) : null;
  const complete = Boolean(
    state &&
    Number(state.expected_count) > 0 &&
    Number(state.imported_count) === Number(state.expected_count) &&
    Number(state.alive_nodes) === Number(state.expected_count) &&
    Number(state.snapshot_nodes) === Number(state.expected_count)
  );
  const fresh = ageSeconds !== null && ageSeconds >= 0 && ageSeconds <= maxAgeSeconds;
  const ok = dbOk && kvOk && complete && fresh;
  return jsonResponse({
    ok,
    ts: checkedAt,
    checks: { db: dbOk, kv: kvOk, snapshot_complete: complete, snapshot_fresh: fresh },
    nodes: {
      total: Number(state?.total_nodes || 0),
      alive: Number(state?.alive_nodes || 0),
      current_snapshot: Number(state?.snapshot_nodes || 0),
    },
    snapshot: state ? {
      id: state.snapshot_id,
      expected: Number(state.expected_count),
      imported: Number(state.imported_count),
      completed_at: Number(state.completed_at),
      age_seconds: ageSeconds,
      max_age_seconds: maxAgeSeconds,
    } : null,
  }, ok ? 200 : 503);
}

async function parseSnapshotRequest(request: Request): Promise<SnapshotImport> {
  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  const raw = await readLimitedRequestText(request);
  if (contentType.includes("application/json")) {
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      throw new Error("invalid JSON body");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("body must be an object");
    const body = value as Record<string, unknown>;
    if (body.version !== 1) throw new Error("unsupported snapshot version");
    if (typeof body.snapshot_id !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(body.snapshot_id)) {
      throw new Error("snapshot_id is missing or invalid");
    }
    if (!Array.isArray(body.nodes)) throw new Error("nodes must be an array");
    if (typeof body.expected_count !== "number") throw new Error("expected_count must be an integer");
    const expectedCount = body.expected_count;
    if (!Number.isInteger(expectedCount) || expectedCount < 1 || expectedCount !== body.nodes.length) {
      throw new Error("expected_count does not match nodes length");
    }
    const nodes = body.nodes.map((node) => validateSnapshotNode(node, true));
    validateSnapshotSet(nodes);
    return { version: 1, snapshotId: body.snapshot_id, expectedCount, nodes, legacy: false };
  }

  let decoded: string;
  try {
    decoded = decodeBase64Utf8(raw);
  } catch {
    throw new Error("invalid base64 body");
  }
  const nodes = decoded.split(/\r?\n/).map((uri) => uri.trim()).filter(Boolean).map((uri) => ({ uri, alive: true }));
  validateSnapshotSet(nodes);
  const digest = (await sha256(decoded)).slice(0, 16);
  return {
    version: 1,
    snapshotId: `legacy-${Date.now()}-${digest}`,
    expectedCount: nodes.length,
    nodes,
    legacy: true,
  };
}

function validateSnapshotNode(value: unknown, requireModel = false): SnapshotNodeInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("each node must be an object");
  const node = value as Record<string, unknown>;
  if (typeof node.uri !== "string") throw new Error("each node requires a URI");
  const uri = node.uri.trim();
  if (node.alive !== true) throw new Error("snapshot nodes must have alive=true");
  let latency = optionalMetric(node.latency_ms, "latency_ms", true);
  let speed = optionalMetric(node.download_speed, "download_speed");
  const model = requireModel ? validateProxyModel(node.model, uri) : null;
  if (model) {
    const modelLatency = optionalMetric(model.latency_ms, "model.latency_ms", true);
    const modelSpeed = optionalMetric(model.download_speed, "model.download_speed");
    if (latency !== undefined && modelLatency !== undefined && latency !== modelLatency) {
      throw new Error("latency_ms conflicts with model.latency_ms");
    }
    if (speed !== undefined && modelSpeed !== undefined && speed !== modelSpeed) {
      throw new Error("download_speed conflicts with model.download_speed");
    }
    if (latency === undefined) latency = modelLatency;
    if (speed === undefined) speed = modelSpeed;
  }
  return { uri, alive: true, latency_ms: latency, download_speed: speed, model };
}

function validateProxyModel(value: unknown, uri: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("each JSON snapshot node requires a model object");
  }
  const model = value as Record<string, unknown>;
  if (model.raw !== uri) throw new Error("model.raw must exactly match uri");
  if (model.alive !== true) throw new Error("model.alive must be true");
  if (typeof model.proto !== "string" || !model.proto.trim()) throw new Error("model.proto must be a string");
  if (typeof model.host !== "string" || !model.host.trim()) throw new Error("model.host must be a string");
  if (typeof model.port !== "number" || !Number.isInteger(model.port) || model.port < 1 || model.port > 65535) {
    throw new Error("model.port must be an integer between 1 and 65535");
  }
  const optionalStrings = [
    "uuid", "password", "method", "sni", "net", "security", "path", "host_header", "flow", "fp", "alpn",
    "pbk", "sid", "country", "source", "content_hash", "name", "transport_mode", "packet_encoding", "protocol",
    "protocol_param", "obfs", "obfs_param", "spider_x", "congestion_control", "udp_relay_mode",
  ];
  for (const field of optionalStrings) {
    if (model[field] !== undefined && model[field] !== null && typeof model[field] !== "string") {
      throw new Error(`model.${field} must be a string or null`);
    }
  }
  for (const field of ["tls", "utls", "skip_cert_verify"]) {
    if (model[field] !== undefined && model[field] !== null && typeof model[field] !== "boolean") {
      throw new Error(`model.${field} must be a boolean or null`);
    }
  }
  if (model.alter_id !== undefined && model.alter_id !== null &&
      (typeof model.alter_id !== "number" || !Number.isSafeInteger(model.alter_id) || model.alter_id < 0)) {
    throw new Error("model.alter_id must be a non-negative integer or null");
  }
  const rendered = uriToClashProxy(uri);
  if (!rendered) throw new Error("model URI is unsupported, malformed, or not representable in Clash");
  if (String(rendered.type) !== model.proto || String(rendered.server).toLowerCase() !== model.host.toLowerCase() ||
      Number(rendered.port) !== model.port) {
    throw new Error("model connection does not match uri");
  }
  return model;
}

function optionalMetric(value: unknown, name: string, integer = false): number | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || (integer && !Number.isSafeInteger(value))) {
    throw new Error(`${name} must be a non-negative${integer ? " integer" : " number"}`);
  }
  return value;
}

async function readLimitedRequestText(request: Request): Promise<string> {
  const declaredLength = request.headers.get("Content-Length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_IMPORT_BODY_BYTES) {
      throw new Error(`request body exceeds ${MAX_IMPORT_BODY_BYTES} bytes`);
    }
  }
  if (!request.body) return "";

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_IMPORT_BODY_BYTES) {
      await reader.cancel();
      throw new Error(`request body exceeds ${MAX_IMPORT_BODY_BYTES} bytes`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new Error("request body is not valid UTF-8");
  }
}

function validateSnapshotSet(nodes: SnapshotNodeInput[]): void {
  if (nodes.length === 0) throw new Error("empty snapshots are not accepted");
  if (nodes.length > MAX_IMPORT_NODES) throw new Error(`snapshot exceeds ${MAX_IMPORT_NODES} nodes`);
  const seen = new Set<string>();
  for (const [index, node] of nodes.entries()) {
    if (!node.uri || node.uri.length > MAX_URI_LENGTH || !/^[a-z0-9]+:\/\//i.test(node.uri)) {
      throw new Error("snapshot contains an invalid URI");
    }
    if (seen.has(node.uri)) throw new Error("snapshot contains duplicate URIs");
    if (!uriToClashProxy(node.uri, index)) {
      throw new Error(`snapshot URI at index ${index} is unsupported, malformed, or not representable in Clash`);
    }
    seen.add(node.uri);
  }
}

async function verifySnapshot(db: D1Database, snapshotId: string, expected: number): Promise<{
  complete: boolean;
  active: number;
  currentSnapshot: string | null;
}> {
  const counts = await db.prepare(
    `SELECT
       COALESCE(SUM(CASE WHEN alive = 1 THEN 1 ELSE 0 END), 0) AS active,
       COALESCE(SUM(CASE WHEN alive = 1 AND snapshot_id = ? THEN 1 ELSE 0 END), 0) AS current_count
     FROM nodes`
  ).bind(snapshotId).first<{ active: number; current_count: number }>();
  const state = await db.prepare("SELECT snapshot_id, expected_count, imported_count FROM import_state WHERE id = 1")
    .first<{ snapshot_id: string; expected_count: number; imported_count: number }>();
  const active = Number(counts?.active || 0);
  const currentCount = Number(counts?.current_count || 0);
  const complete = Boolean(
    state && state.snapshot_id === snapshotId && Number(state.expected_count) === expected &&
    Number(state.imported_count) === expected && active === expected && currentCount === expected
  );
  return { complete, active, currentSnapshot: state?.snapshot_id || null };
}

interface ParsedUri {
  proto: string;
  host: string | null;
  port: number | null;
}

function quickParse(uri: string): ParsedUri {
  const protocol = uri.match(/^([a-z0-9]+):\/\//i)?.[1].toLowerCase() || "unknown";
  const clash = uriToClashProxy(uri);
  return {
    proto: protocol,
    host: clash && typeof clash.server === "string" ? clash.server : null,
    port: clash && typeof clash.port === "number" ? clash.port : null,
  };
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function positiveInteger(value: string | undefined): number | null {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function subResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": 'attachment; filename="sub.txt"',
      "Cache-Control": "no-cache",
    },
  });
}

function clashResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/yaml; charset=utf-8",
      "Content-Disposition": 'attachment; filename="clash.yaml"',
      "Cache-Control": "no-cache",
    },
  });
}

function renderUnavailableResponse(clash: boolean): Response {
  return clash ? clashResponse("# snapshot unavailable\n", 503) : subResponse("", 503);
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
