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
      return handleImport(request, env, ctx);
    }

    return new Response("Not Found", { status: 404 });
  },

  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    await refreshUpstreams(env);
  },
};

async function handleSub(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const format = (url.searchParams.get("format") || "").toLowerCase();

  // KV cache key per format
  const cacheKey = format === "clash" ? "sub-render-clash" : SUB_CACHE_KEY;
  const cached = await env.CACHE.get(cacheKey, "text");
  if (cached !== null) {
    return format === "clash" ? clashResponse(cached) : subResponse(cached);
  }

  // 2. Query D1 for alive nodes ordered by download speed (desc) then latency (asc).
  //    download_speed NULL sorts last (COALESCE to -1 so NULLs never beat real speeds).
  //    latency_ms NULL also sorts last (COALESCE to 999999) — SQLite defaults NULLS FIRST
  //    in ASC, which would put untested nodes before fast ones; this fixes that.
  const { results } = await env.DB.prepare(
    "SELECT uri FROM nodes WHERE alive = 1 ORDER BY COALESCE(download_speed, -1) DESC, COALESCE(latency_ms, 999999) ASC"
  ).all<{ uri: string }>();

  const uris = (results ?? []).map((r) => r.uri).filter((u) => !!u);

  let body: string;
  let render: (s: string) => Response;
  if (format === "clash") {
    // Rebuild clash YAML proxies from URIs so Clash Verge can subscribe directly.
    const proxies = uris.map((u, i) => uriToClashDict(u, i)).filter(Boolean);
    const doc = { proxies };
    body = yamlDump(doc);
    render = clashResponse;
  } else {
    body = base64Encode(uris.join("\n"));
    render = subResponse;
  }

  // 3. Write to KV (TTL 60s) via waitUntil (don't block response)
  ctx.waitUntil(env.CACHE.put(cacheKey, body, { expirationTtl: SUB_CACHE_TTL }));

  return render(body);
}

async function handleImport(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
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

  // Mark ALL existing rows dead BEFORE re-upserting the fresh snapshot.
  // This closes the clobber bug: stale dead nodes from a prior publish that
  // are no longer in the fresh snapshot must NOT linger alive=1, otherwise
  // /sub WHERE alive=1 keeps serving nodes that a later verify marked dead.
  await env.DB.prepare("UPDATE nodes SET alive = 0").run();

  // Batch upsert via INSERT OR REPLACE. Fresh snapshot rows land alive=1.
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

  // Purge KV render cache so /sub reflects the fresh snapshot immediately
  // instead of waiting for the 60s TTL to expire.
  ctx.waitUntil(Promise.all([
    env.CACHE.delete("sub-render"),
    env.CACHE.delete("sub-render-clash"),
  ]).catch(() => {}));

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

function clashResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/yaml; charset=utf-8",
      "Content-Disposition": 'attachment; filename="clash.yaml"',
      "Cache-Control": "no-cache",
    },
  });
}

// Rebuild a clash proxy dict from a v2ray URI string.
// Supports vmess:// (base64 JSON), vless://, trojan://, ss:// (SIP002).
function uriToClashDict(uri: string, idx: number): Record<string, unknown> | null {
  try {
    const m = uri.match(/^([a-z0-9]+):\/\//i);
    if (!m) return null;
    const proto = m[1].toLowerCase();

    if (proto === "vmess") {
      // vmess://<base64 json>
      const json = JSON.parse(base64Decode(uri.slice(8)));
      const name = json.ps || `vmess-${idx}`;
      const d: Record<string, unknown> = {
        name: `${name}-${json.add}:${json.port}`,
        type: "vmess",
        server: json.add,
        port: Number(json.port),
        uuid: json.id,
        alterId: Number(json.aid ?? 0),
        cipher: json.cipher || "auto",
        udp: true,
        network: json.net || "tcp",
        tls: json.tls === "tls" ? true : false,
      };
      if (json.path) d["path"] = json.path;
      if (json.host) d["servername"] = json.host;
      if (json.sni) d["sni"] = json.sni;
      return d;
    }

    if (proto === "vless" || proto === "trojan") {
      // scheme://userinfo@host:port?params#name
      const u = new URL(uri);
      const host = u.hostname;
      const port = Number(u.port) || 443;
      const name = decodeURIComponent(u.hash.slice(1)) || `${proto}-${host}:${port}`;
      const params = u.searchParams;
      const d: Record<string, unknown> = {
        name: `${name}-${host}:${port}`,
        type: proto,
        server: host,
        port,
        udp: true,
        network: params.get("type") || "tcp",
        tls: true,
      };
      if (proto === "vless") d["uuid"] = u.username;
      if (proto === "trojan") d["password"] = decodeURIComponent(u.username);
      if (params.get("sni")) d["sni"] = params.get("sni");
      if (params.get("path")) d["path"] = params.get("path");
      if (params.get("host")) d["servername"] = params.get("host");
      if (params.get("flow")) d["flow"] = params.get("flow");
      if (params.get("pbk")) {
        d["reality-opts"] = { "public-key": params.get("pbk"), "short-id": params.get("sid") || "" };
      }
      if (params.get("fp")) d["client-fingerprint"] = params.get("fp");
      return d;
    }

    if (proto === "ss") {
      // SIP002: ss://base64(method:password)@host:port#name
      //       or ss://method:password@host:port#name (plain)
      // Use regex to avoid new URL mangling base64 (= chars, padding).
      const ssMatch = uri.match(/^ss:\/\/([^@?#]+)@([^:#?]+)(?::(\d+))?(?:\?(.*?))?(?:#(.*))?$/i);
      if (!ssMatch) return null;
      // URL-decode userinfo first (SIP002 b64 may be %-encoded, e.g. %3D = =)
      let userinfo = decodeURIComponent(ssMatch[1]);
      const host = ssMatch[2];
      const port = ssMatch[3] ? Number(ssMatch[3]) : 8388;
      // Decode base64 userinfo if it has no ':' (SIP002 b64 blob)
      if (userinfo && !userinfo.includes(":")) {
        try {
          const dec = base64Decode(userinfo);
          if (dec.includes(":")) userinfo = dec;
        } catch {
          /* keep raw */
        }
      }
      let method = "aes-256-gcm";
      let password = "";
      if (userinfo.includes(":")) {
        const idx = userinfo.indexOf(":");
        method = userinfo.slice(0, idx);
        password = userinfo.slice(idx + 1);
      }
      const nameRaw = ssMatch[5] ? decodeURIComponent(ssMatch[5]) : "";
      const name = nameRaw || `ss-${host}:${port}`;
      return {
        name: `${name}-${host}:${port}`,
        type: "ss",
        server: host,
        port,
        cipher: method,
        password,
        udp: true,
      };
    }

    return null;
  } catch {
    return null;
  }
}

// Minimal YAML emitter for {proxies: [...]}. No external deps.
function yamlDump(obj: Record<string, unknown>): string {
  if (!obj.proxies || !Array.isArray(obj.proxies)) return "proxies: []\n";
  let out = "proxies:\n";
  for (const p of obj.proxies) {
    if (!p || typeof p !== "object") continue;
    out += "  - ";
    const entries = Object.entries(p as Record<string, unknown>);
    for (let i = 0; i < entries.length; i++) {
      const [k, v] = entries[i];
      if (i > 0) out += "    ";
      out += `${k}: ${yamlVal(v)}\n`;
    }
  }
  return out;
}

function yamlVal(v: unknown): string {
  if (v === null || v === undefined) return '""';
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "object") {
    // inline dict or array
    return JSON.stringify(v);
  }
  // string — quote if contains special chars
  const s = String(v);
  if (/[:#\[\]{},&*?|<>=!%@`"'\n]/.test(s)) {
    return `"${s.replace(/"/g, '\\"')}"`;
  }
  return s;
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

// btoa() cannot encode strings with chars > 0xff (URI names may contain
// emoji / CJK in the vmess base64-JSON or the fragment). Encode as UTF-8
// bytes first, then btoa the resulting binary string.
function base64Encode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64Decode(s: string): string {
  // atob returns a binary string; decode back to UTF-8 string.
  const binary = atob(s.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
