import { describe, expect, it, vi } from "vitest";
import { parseDocument } from "yaml";

import worker, { type Env, handleImport, handleSub } from "./sub-aggregator";
import { decodeBase64Utf8 } from "./subscription";

interface BoundStatement {
  sql: string;
  args: unknown[];
  bind: (...args: unknown[]) => BoundStatement;
  first: <T>() => Promise<T | null>;
  all: <T>() => Promise<{ results: T[] }>;
}

function fakeEnvironment(options: {
  batchFailure?: boolean;
  staleCompletedAt?: number;
  cacheKeys?: string[];
  expectedCount?: number;
} = {}) {
  const batches: BoundStatement[][] = [];
  const deleted: string[] = [];
  const now = Date.now();
  const expectedCount = options.expectedCount ?? 2;
  const state = {
    snapshot_id: "run-1",
    expected_count: expectedCount,
    imported_count: expectedCount,
    completed_at: options.staleCompletedAt ?? now,
  };
  const prepare = (sql: string): BoundStatement => {
    const statement: BoundStatement = {
      sql,
      args: [],
      bind(...args: unknown[]) {
        return { ...statement, args };
      },
      async first<T>() {
        if (sql.includes("AS active,")) return { active: expectedCount, current_count: expectedCount } as T;
        if (sql.includes("AS total_nodes")) {
          return {
            ...state,
            total_nodes: expectedCount,
            alive_nodes: expectedCount,
            snapshot_nodes: expectedCount,
          } as T;
        }
        if (sql.includes("FROM import_state")) return state as T;
        return null;
      },
      async all<T>() {
        return { results: [] as T[] };
      },
    };
    return statement;
  };
  const db = {
    prepare,
    async batch(statements: BoundStatement[]) {
      batches.push(statements);
      return statements.map((_, index) => ({
        success: !(options.batchFailure && index === 0),
        meta: { changes: index === 1 ? 3 : 1 },
        results: [],
      }));
    },
  };
  const cache = {
    async delete(key: string) {
      deleted.push(key);
      return true;
    },
    async get() {
      return null;
    },
    async put() {
      return undefined;
    },
    async list() {
      return {
        keys: (options.cacheKeys || []).map((name) => ({ name })),
        list_complete: true,
        cacheStatus: null,
      };
    },
  };
  return {
    env: { DB: db, CACHE: cache, ADMIN_TOKEN: "secret" } as unknown as Env,
    batches,
    deleted,
    state,
  };
}

function snapshotRequest(body: unknown): Request {
  return new Request("https://worker.example/admin/import", {
    method: "POST",
    headers: { "X-Admin-Token": "secret", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

const trojanUri = "trojan://one@one.example:443#one";
const vlessUri = "vless://two@two.example:443?security=tls#two";
const nodes = [
  {
    uri: trojanUri,
    alive: true,
    latency_ms: 50,
    download_speed: 10.5,
    model: {
      proto: "trojan", host: "one.example", port: 443, password: "one", raw: trojanUri,
      alive: true, latency_ms: 50, download_speed: 10.5, source: "test",
    },
  },
  {
    uri: vlessUri,
    alive: true,
    latency_ms: 75,
    download_speed: 8,
    model: {
      proto: "vless", host: "two.example", port: 443, uuid: "two", security: "tls", tls: true,
      net: "tcp", raw: vlessUri, alive: true, latency_ms: 75, download_speed: 8, source: "test",
    },
  },
];

interface RenderState {
  snapshot_id: string;
  expected_count: number;
  imported_count: number;
  completed_at: number;
}

function renderEnvironment(
  states: Array<RenderState | null>,
  rowsBySnapshot: Record<string, string[]>,
  initialCache: Record<string, string> = {}
) {
  let stateRead = 0;
  const gets: string[] = [];
  const puts: string[] = [];
  const pending: Promise<unknown>[] = [];
  const cacheValues = new Map(Object.entries(initialCache));

  const statement = (sql: string, args: unknown[] = []): BoundStatement => ({
    sql,
    args,
    bind: (...nextArgs: unknown[]) => statement(sql, nextArgs),
    async first<T>() {
      if (!sql.includes("FROM import_state")) return null;
      const value = states[Math.min(stateRead, states.length - 1)] ?? null;
      stateRead += 1;
      return value as T | null;
    },
    async all<T>() {
      if (!sql.includes("SELECT uri FROM nodes")) return { results: [] as T[] };
      const version = sql.includes("snapshot_id IS NULL") ? "legacy" : String(args[0]);
      return { results: (rowsBySnapshot[version] || []).map((uri) => ({ uri })) as T[] };
    },
  });
  const db = { prepare: (sql: string) => statement(sql) };
  const cache = {
    async get(key: string) {
      gets.push(key);
      return cacheValues.get(key) ?? null;
    },
    async put(key: string, value: string) {
      puts.push(key);
      cacheValues.set(key, value);
    },
  };
  const context = {
    waitUntil(promise: Promise<unknown>) {
      pending.push(Promise.resolve(promise));
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
  return {
    env: { DB: db, CACHE: cache, ADMIN_TOKEN: "secret" } as unknown as Env,
    context,
    gets,
    puts,
    pending,
  };
}

describe("snapshot import", () => {
  it("rejects count mismatches before touching D1", async () => {
    const { env, batches } = fakeEnvironment();
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: 3,
      nodes,
    }), env);
    expect(response.status).toBe(400);
    expect(batches).toHaveLength(0);
  });

  it("rejects a non-numeric expected_count instead of coercing it", async () => {
    const { env, batches } = fakeEnvironment();
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: "2",
      nodes,
    }), env);
    expect(response.status).toBe(400);
    expect(batches).toHaveLength(0);
  });

  it("rejects duplicate URIs before touching D1", async () => {
    const { env, batches } = fakeEnvironment();
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: 2,
      nodes: [nodes[0], nodes[0]],
    }), env);
    expect(response.status).toBe(400);
    expect(batches).toHaveLength(0);
  });

  it("rejects unknown and malformed URIs before touching D1", async () => {
    for (const uri of ["unknown://credential@example.com:443", "tuic://user@example.com:443"]) {
      const { env, batches } = fakeEnvironment();
      const response = await handleImport(snapshotRequest({
        version: 1,
        snapshot_id: "invalid-run",
        expected_count: 1,
        nodes: [{
          uri,
          alive: true,
          model: { proto: uri.split(":", 1)[0], host: "example.com", port: 443, raw: uri, alive: true },
        }],
      }), env);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ ok: false });
      expect(batches).toHaveLength(0);
    }
  });

  it("imports credential URIs on explicit port 80", async () => {
    const uri = "vless://id@example.com:80?security=none&type=ws#port-80";
    const { env, batches } = fakeEnvironment({ expectedCount: 1 });
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: 1,
      nodes: [{
        uri,
        alive: true,
        model: {
          proto: "vless", host: "example.com", port: 80, uuid: "id",
          security: "none", tls: false, net: "ws", raw: uri, alive: true,
        },
      }],
    }), env);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, complete: true, imported: 1 });
    expect(batches).toHaveLength(1);
  });

  it("requires a matching complete model for JSON snapshots", async () => {
    for (const node of [
      { uri: trojanUri, alive: true },
      { ...nodes[0], model: { ...nodes[0].model, raw: "trojan://different@one.example:443" } },
    ]) {
      const { env, batches } = fakeEnvironment();
      const response = await handleImport(snapshotRequest({
        version: 1,
        snapshot_id: "bad-model",
        expected_count: 1,
        nodes: [node],
      }), env);
      expect(response.status).toBe(400);
      expect(batches).toHaveLength(0);
    }
  });

  it("rejects fractional latency values", async () => {
    const { env, batches } = fakeEnvironment();
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "fractional-latency",
      expected_count: 1,
      nodes: [{
        ...nodes[0],
        latency_ms: 1.5,
        model: { ...nodes[0].model, latency_ms: 1.5 },
      }],
    }), env);
    expect(response.status).toBe(400);
    expect(batches).toHaveLength(0);
  });

  it("uses one atomic upsert/stale/state batch and verifies completion", async () => {
    const priorKey = "sub-render-v3:run-0:1";
    const { env, batches, deleted } = fakeEnvironment({ cacheKeys: [priorKey] });
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: 2,
      nodes,
    }), env);
    const result = await response.json() as Record<string, unknown>;
    expect(response.status).toBe(200);
    expect(result).toMatchObject({
      ok: true, complete: true, imported: 2, expected: 2, stale_disabled: 3, model_persisted: true,
    });
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(3);
    expect(batches[0][0].sql).toContain("ON CONFLICT(uri) DO UPDATE");
    expect(batches[0][0].sql).toContain("FROM json_each(?)");
    expect(batches[0][0].sql).toContain("COALESCE(excluded.latency_ms, nodes.latency_ms)");
    expect(batches[0][0].sql).toContain("node_json = excluded.node_json");
    expect(batches[0][0].sql).toContain("packet_encoding = excluded.packet_encoding");
    expect(batches[0][0].sql).toContain("udp_relay_mode = excluded.udp_relay_mode");
    for (const field of [
      "alter_id", "transport_mode", "packet_encoding", "spider_x", "utls", "protocol",
      "protocol_param", "obfs", "obfs_param", "congestion_control", "udp_relay_mode",
    ]) {
      expect(batches[0][0].sql).toContain(`$.model.${field}`);
      expect(batches[0][0].sql).toContain(`${field} = excluded.${field}`);
    }
    expect(batches[0][0].args).toHaveLength(4);
    const incoming = JSON.parse(String(batches[0][0].args[0])) as Array<Record<string, unknown>>;
    expect(incoming).toHaveLength(2);
    expect(incoming[0]).toMatchObject({
      uri: trojanUri,
      model: { proto: "trojan", raw: trojanUri, source: "test" },
    });
    expect(incoming[1]).toMatchObject({
      uri: vlessUri,
      model: { uuid: "two", net: "tcp", tls: true },
    });
    expect(batches[0][1].sql).toContain("snapshot_id <> ?");
    expect(batches[0][2].sql).toContain("import_state");
    expect(batches[0].some((statement) => statement.sql === "UPDATE nodes SET alive = 0")).toBe(false);
    expect(deleted).toEqual(expect.arrayContaining([
      "sub-render",
      "sub-render-clash",
      "sub-render-v2",
      "sub-render-clash-v2",
    ]));
    expect(deleted).not.toContain(priorKey);
  });

  it("imports a full 100-node publish with only three D1 batch statements", async () => {
    const hundredNodes = Array.from({ length: 100 }, (_, index) => {
      const uri = `trojan://secret-${index}@node-${index}.example:443#node-${index}`;
      return {
        uri,
        alive: true,
        latency_ms: index,
        download_speed: 100 - index,
        model: {
          proto: "trojan", host: `node-${index}.example`, port: 443,
          password: `secret-${index}`, raw: uri, alive: true,
          latency_ms: index, download_speed: 100 - index, source: "limit-test",
        },
      };
    });
    const { env, batches } = fakeEnvironment({ expectedCount: 100 });
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: 100,
      nodes: hundredNodes,
    }), env);
    expect(response.status).toBe(200);
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(3);
    const incoming = JSON.parse(String(batches[0][0].args[0])) as unknown[];
    expect(incoming).toHaveLength(100);
  });

  it("rejects snapshots above the 100-node publish boundary before touching D1", async () => {
    const tooMany = Array.from({ length: 101 }, (_, index) => {
      const uri = `trojan://secret-${index}@node-${index}.example:443#node-${index}`;
      return {
        uri,
        alive: true,
        model: {
          proto: "trojan", host: `node-${index}.example`, port: 443,
          password: `secret-${index}`, raw: uri, alive: true,
        },
      };
    });
    const { env, batches } = fakeEnvironment({ expectedCount: 101 });
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "too-large",
      expected_count: 101,
      nodes: tooMany,
    }), env);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ ok: false, error: "snapshot exceeds 100 nodes" });
    expect(batches).toHaveLength(0);
  });

  it("rejects an oversized request before parsing or touching D1", async () => {
    const { env, batches } = fakeEnvironment();
    const request = new Request("https://worker.example/admin/import", {
      method: "POST",
      headers: {
        "X-Admin-Token": "secret",
        "Content-Type": "application/json",
        "Content-Length": String(1024 * 1024 + 1),
      },
      body: "{}",
    });
    const response = await handleImport(request, env);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ ok: false, error: "request body exceeds 1048576 bytes" });
    expect(batches).toHaveLength(0);
  });

  it("reports a partial batch result as incomplete", async () => {
    const { env } = fakeEnvironment({ batchFailure: true });
    const response = await handleImport(snapshotRequest({
      version: 1,
      snapshot_id: "run-1",
      expected_count: 2,
      nodes,
    }), env);
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({ ok: false, complete: false });
  });
});

describe("versioned subscription cache", () => {
  const oldState = { snapshot_id: "run-old", expected_count: 1, imported_count: 1, completed_at: 100 };
  const newState = { snapshot_id: "run-new", expected_count: 1, imported_count: 1, completed_at: 200 };
  const oldUri = "trojan://old@old.example:443#old";
  const newUri = "trojan://new@new.example:443#new";

  it("renders strict Clash YAML for backslash-bearing transport values", async () => {
    const escapedUri =
      "vless://id@example.com:443?security=tls&type=ws&" +
      "path=%2Fws%3Fed%5C%3D2560&host=edge.example#node%3A%20%5Cq";
    const { env, context, gets, puts, pending } = renderEnvironment(
      [newState],
      { "run-new": [escapedUri] }
    );

    const response = await handleSub(
      new Request("https://worker.example/sub?format=clash"),
      env,
      context
    );
    await Promise.all(pending);
    const document = parseDocument(await response.text());

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("text/yaml");
    expect(document.errors).toHaveLength(0);
    expect(document.toJS()).toMatchObject({
      proxies: [{ name: "node: \\q", "ws-opts": { path: "/ws?ed\\=2560" } }],
    });
    expect(gets).toEqual(["sub-render-clash-v3:run-new:200"]);
    expect(puts).toEqual(["sub-render-clash-v3:run-new:200"]);
  });

  it("isolates a late stale write under the prior snapshot cache key", async () => {
    const oldKey = "sub-render-v3:run-old:100";
    const { env, context, gets, puts, pending } = renderEnvironment(
      [newState, newState],
      { "run-new": [newUri] },
      { [oldKey]: "late stale value" }
    );
    const response = await handleSub(new Request("https://worker.example/sub"), env, context);
    await Promise.all(pending);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Disposition")).toContain("sub.txt");
    expect(decodeBase64Utf8(await response.text())).toBe(newUri);
    expect(gets).toEqual(["sub-render-v3:run-new:200"]);
    expect(puts).toEqual(["sub-render-v3:run-new:200"]);
    expect(gets).not.toContain(oldKey);
  });

  it("retries when import_state changes while nodes are being read", async () => {
    const { env, context, gets, puts, pending } = renderEnvironment(
      [oldState, newState, newState, newState],
      { "run-old": [oldUri], "run-new": [newUri] }
    );
    const response = await handleSub(new Request("https://worker.example/sub"), env, context);
    await Promise.all(pending);
    expect(response.status).toBe(200);
    expect(decodeBase64Utf8(await response.text())).toBe(newUri);
    expect(gets).toEqual(["sub-render-v3:run-old:100", "sub-render-v3:run-new:200"]);
    expect(puts).toEqual(["sub-render-v3:run-new:200"]);
  });

  it("retries when import_state changes after rendering but before the response", async () => {
    const { env, context, gets, puts, pending } = renderEnvironment(
      [oldState, oldState, newState, newState, newState, newState],
      { "run-old": [oldUri], "run-new": [newUri] }
    );
    const response = await handleSub(new Request("https://worker.example/sub"), env, context);
    await Promise.all(pending);
    expect(response.status).toBe(200);
    expect(decodeBase64Utf8(await response.text())).toBe(newUri);
    expect(gets).toEqual(["sub-render-v3:run-old:100", "sub-render-v3:run-new:200"]);
    expect(puts).toEqual(["sub-render-v3:run-new:200"]);
  });
});

describe("health endpoint", () => {
  const context = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;

  it("returns 200 only for a complete, recent snapshot and reachable KV", async () => {
    const { env } = fakeEnvironment();
    const response = await worker.fetch(new Request("https://worker.example/health"), env, context);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      ok: true,
      checks: { db: true, kv: true, snapshot_complete: true, snapshot_fresh: true },
    });
  });

  it("returns 503 for a stale snapshot", async () => {
    const { env } = fakeEnvironment({ staleCompletedAt: Date.now() - 9 * 60 * 60 * 1000 });
    const response = await worker.fetch(new Request("https://worker.example/health"), env, context);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ ok: false, checks: { snapshot_fresh: false } });
  });

  it("returns 503 when a corrupt snapshot timestamp is in the future", async () => {
    const { env } = fakeEnvironment({ staleCompletedAt: Date.now() + 60_000 });
    const response = await worker.fetch(new Request("https://worker.example/health"), env, context);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ ok: false, checks: { snapshot_fresh: false } });
  });
});
