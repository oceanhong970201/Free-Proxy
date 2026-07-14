// proxy-sub-aggregator — Cloudflare Worker
// Endpoints:
//   GET  /sub           -> base64-joined alive nodes (KV-cached 60s)
//   POST /admin/import  -> upsert base64 node list into D1 (X-Admin-Token)
//   GET  /health        -> {ok, ts}
//   scheduled (cron)    -> refreshUpstreams (stub)

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ADMIN_TOKEN: string;
}

const SUB_CACHE_KEY = "sub-render";
const SUB_CACHE_TTL = 60; // seconds

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === "/health") {
      return jsonResponse({ ok: true, ts: Date.now() });
    }

    if (pathname === "/sub") {
      return handleSub(request, env, ctx);
    }

    if (pathname === "/admin/import" && request.method === "POST") {
      return handleImport(request, env);
    }

    return new Response("Not Found", { status: 404 });
  },

  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    await refreshUpstreams(env);
  },
};

async function handleSub(_request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  // 1. KV cache lookup
  const cached = await env.CACHE.get(SUB_CACHE_KEY, "text");
  if (cached !== null) {
    return subResponse(cached);
  }

  // 2. Query D1 for alive nodes ordered by download speed (desc) then latency (asc).
  //    download_speed NULL sorts last (COALESCE to -1 so NULLs never beat real speeds).
  //    latency_ms NULL also sorts last (COALESCE to 999999) — SQLite defaults NULLS FIRST
  //    in ASC, which would put untested nodes before fast ones; this fixes that.
  const { results } = await env.DB.prepare(
    "SELECT uri FROM nodes WHERE alive = 1 ORDER BY COALESCE(download_speed, -1) DESC, COALESCE(latency_ms, 999999) ASC"
  ).all<{ uri: string }>();

  const uris = (results ?? []).map((r) => r.uri).filter((u) => !!u);
  const body = base64Encode(uris.join("\n"));

  // 3. Write to KV (TTL 60s) via waitUntil (don't block response)
  ctx.waitUntil(env.CACHE.put(SUB_CACHE_KEY, body, { expirationTtl: SUB_CACHE_TTL }));

  return subResponse(body);
}

async function handleImport(request: Request, env: Env): Promise<Response> {
  const token = request.headers.get("X-Admin-Token");
  if (!token || token !== env.ADMIN_TOKEN) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }

  const raw = await request.text();
  let uris: string[] = [];
  try {
    const decoded = base64Decode(raw);
    uris = decoded
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  } catch {
    return jsonResponse({ error: "invalid base64 body" }, 400);
  }

  if (uris.length === 0) {
    return jsonResponse({ imported: 0 });
  }

  // Batch upsert via INSERT OR REPLACE
  const stmt = env.DB.prepare(
    `INSERT OR REPLACE INTO nodes (uri, proto, host, port, alive, first_seen, last_checked, content_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const now = Date.now();
  // Pre-compute content_hash (async sha256) BEFORE binding — otherwise
  // stmt.bind receives a Promise and the Worker throws Error 1101.
  const parsed = uris.map((uri) => ({ uri, ...quickParse(uri) }));
  const hashes = await Promise.all(parsed.map((p) => hash(p.uri)));
  const batch = parsed.map((p, i) =>
    stmt.bind(p.uri, p.proto, p.host, p.port, 1, now, now, hashes[i])
  );

  const results = await env.DB.batch(batch);
  const imported = results.filter((r) => r.success).length;
  return jsonResponse({ imported });
}

async function refreshUpstreams(env: Env): Promise<void> {
  // Stub: pull upstream sources, parse, upsert. Logging only for now.
  console.log("refreshUpstreams tick", new Date().toISOString());
  // Touch D1 to keep connection warm (no-op safe).
  await env.DB.prepare("SELECT 1").first();
}

// ---- helpers ----

function subResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": 'attachment; filename="sub.txt"',
      "Cache-Control": "no-cache",
    },
  });
}

function jsonResponse(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

interface Parsed {
  proto: string | null;
  host: string | null;
  port: number | null;
}

// Best-effort URI scheme parse for upsert population (non-fatal).
function quickParse(uri: string): Parsed {
  try {
    const m = uri.match(/^([a-z0-9]+):\/\/([^:/?#]+)(?::(\d+))?/i);
    if (!m) return { proto: null, host: null, port: null };
    return {
      proto: m[1].toLowerCase(),
      host: m[2],
      port: m[3] ? Number(m[3]) : null,
    };
  } catch {
    return { proto: null, host: null, port: null };
  }
}

async function hash(s: string): Promise<string> {
  const data = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// atob / btoa are available in the Workers runtime.
function base64Encode(s: string): string {
  return btoa(s);
}

function base64Decode(s: string): string {
  return atob(s.trim());
}
