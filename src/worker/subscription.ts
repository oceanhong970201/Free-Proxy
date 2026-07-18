import { stringify } from "yaml";

export type ClashProxy = Record<string, unknown> & { name: string };

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function requiredPort(value: unknown): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error("missing or invalid port");
  return port;
}

function booleanValue(value: string | null): boolean {
  return value !== null && ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function alpnValue(value: string | null): string[] | undefined {
  if (!value) return undefined;
  const values = value.split(",").map((item) => item.trim()).filter(Boolean);
  return values.length > 0 ? values : undefined;
}

export function decodeBase64Utf8(value: string): string {
  let normalized = value.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!normalized || normalized.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error("invalid base64");
  }
  normalized = normalized.replace(/=+$/, "");
  normalized += "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
}

export function encodeBase64Utf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function displayName(fragment: string, fallback: string): string {
  const decoded = decodeComponent(fragment);
  return decoded.trim() || fallback;
}

function applyTransport(
  proxy: Record<string, unknown>,
  networkValue: string | null,
  path: string | null,
  host: string | null,
  serviceName: string | null,
  earlyData: string | null,
  earlyDataHeader: string | null,
  transportMode: string | null
): void {
  const requestedNetwork = (networkValue || "tcp").toLowerCase();
  const network = requestedNetwork === "raw"
    ? "tcp"
    : requestedNetwork === "websocket"
      ? "ws"
    : requestedNetwork === "http-upgrade" || requestedNetwork === "http_upgrade"
      ? "httpupgrade"
      : requestedNetwork === "splithttp"
        ? "xhttp"
        : requestedNetwork;
  proxy.network = network;

  if (network === "ws") {
    const options: Record<string, unknown> = {};
    if (path) options.path = path;
    if (host) options.headers = { Host: host };
    const maxEarlyData = Number(earlyData);
    if (Number.isFinite(maxEarlyData) && maxEarlyData > 0) options["max-early-data"] = maxEarlyData;
    if (earlyDataHeader) options["early-data-header-name"] = earlyDataHeader;
    if (Object.keys(options).length > 0) proxy["ws-opts"] = options;
    return;
  }

  if (network === "grpc") {
    const options: Record<string, unknown> = {};
    if (serviceName || path) options["grpc-service-name"] = serviceName || path;
    if (Object.keys(options).length > 0) proxy["grpc-opts"] = options;
    return;
  }

  if (network === "h2") {
    const options: Record<string, unknown> = {};
    if (path) options.path = path;
    if (host) options.host = [host];
    if (Object.keys(options).length > 0) proxy["h2-opts"] = options;
    return;
  }

  if (network === "http") {
    const options: Record<string, unknown> = { method: "GET" };
    if (path) options.path = [path];
    if (host) options.headers = { Host: [host] };
    proxy["http-opts"] = options;
    return;
  }

  if (network === "xhttp" || network === "httpupgrade") {
    const options: Record<string, unknown> = {};
    if (path) options.path = path;
    if (host) options.host = host;
    if (network === "xhttp" && transportMode) options.mode = transportMode;
    proxy[network === "xhttp" ? "xhttp-opts" : "http-upgrade-opts"] = options;
    return;
  }

  if (network !== "tcp") throw new Error(`unsupported Clash transport: ${network}`);
}

function parseVmess(uri: string, index: number): ClashProxy {
  const encoded = decodeComponent(uri.slice("vmess://".length));
  const source = JSON.parse(decodeBase64Utf8(encoded)) as Record<string, unknown>;
  const server = String(source.add || "").trim();
  const uuid = String(source.id || "").trim();
  if (!server || !uuid) throw new Error("vmess is missing server or uuid");
  const port = requiredPort(source.port);
  const fallback = `vmess-${server}:${port}`;
  const proxy: ClashProxy = {
    name: displayName(String(source.ps || ""), fallback),
    type: "vmess",
    server,
    port,
    uuid,
    alterId: Number.isFinite(Number(source.aid)) ? Number(source.aid) : 0,
    cipher: String(source.scy || source.cipher || "auto"),
    udp: true,
  };
  let network = String(source.net || "tcp").toLowerCase();
  const vmessType = String(source.type || source.mode || "").trim().toLowerCase();
  if (network === "tcp" && vmessType === "http") network = "http";
  if (network === "grpc") {
    if (vmessType && vmessType !== "none" && vmessType !== "gun") {
      throw new Error(`unsupported VMess gRPC mode: ${vmessType}`);
    }
    if (String(source.authority || source.host || "").trim()) {
      throw new Error("VMess gRPC authority is not representable in Clash");
    }
  }
  let vmessTransportMode = source.mode || source.type ? String(source.mode || source.type).trim().toLowerCase() : "";
  if (network === "xhttp" || network === "splithttp") {
    vmessTransportMode = vmessTransportMode && vmessTransportMode !== "none" ? vmessTransportMode : "auto";
    if (!["auto", "packet-up", "stream-up", "stream-one"].includes(vmessTransportMode)) {
      throw new Error(`unsupported VMess XHTTP mode: ${vmessTransportMode}`);
    }
  }
  applyTransport(
    proxy,
    network,
    source.path ? String(source.path) : null,
    source.host ? String(source.host) : null,
    source.serviceName ? String(source.serviceName) : null,
    source.ed ? String(source.ed) : null,
    source.eh ? String(source.eh) : null,
    vmessTransportMode || null
  );
  const security = String(source.tls || source.security || "").toLowerCase();
  if (security === "tls" || security === "reality") proxy.tls = true;
  const serverName = String(source.sni || source.servername || "").trim();
  if (serverName) proxy.servername = serverName;
  if (source.alpn) proxy.alpn = alpnValue(String(source.alpn));
  if (source.fp) proxy["client-fingerprint"] = String(source.fp);
  if (source.allowInsecure !== undefined) {
    proxy["skip-cert-verify"] = booleanValue(String(source.allowInsecure));
  }
  if (!proxy.name) proxy.name = `vmess-${index}`;
  return proxy;
}

interface CredentialUri {
  credential: string;
  host: string;
  port: number;
  params: URLSearchParams;
  fragment: string;
}

function parseCredentialUri(uri: string): CredentialUri {
  const schemeAt = uri.indexOf("://");
  const hashAt = uri.indexOf("#", schemeAt + 3);
  const fragment = hashAt >= 0 ? uri.slice(hashAt + 1) : "";
  const withoutFragment = hashAt >= 0 ? uri.slice(0, hashAt) : uri;
  // A transport path or another query value may legitimately contain a raw
  // `@`.  Only the authority section can contain the credential delimiter;
  // searching the complete URI would mistake a query value for the endpoint.
  const queryAt = withoutFragment.indexOf("?", schemeAt + 3);
  const authorityEnd = queryAt >= 0 ? queryAt : withoutFragment.length;
  const at = withoutFragment.lastIndexOf("@", authorityEnd - 1);
  if (schemeAt < 0 || at <= schemeAt + 3) throw new Error("missing credential or endpoint");
  const credential = decodeComponent(withoutFragment.slice(schemeAt + 3, at));
  const endpoint = withoutFragment.slice(at + 1);
  // Use a non-special URL scheme so WHATWG URL does not normalize explicit
  // default ports (for example `:80`) to an empty string.
  const parsed = new URL(`proxy://${endpoint}`);
  const host = stripIpv6Brackets(parsed.hostname);
  if (!credential || !host) throw new Error("missing credential or host");
  return {
    credential,
    host,
    port: requiredPort(parsed.port),
    params: parsed.searchParams,
    fragment,
  };
}

function applyUrlTls(proxy: Record<string, unknown>, params: URLSearchParams, trojan: boolean): void {
  const security = (params.get("security") || (trojan ? "tls" : "none")).toLowerCase();
  if (!["none", "tls", "reality"].includes(security)) throw new Error(`unsupported security mode: ${security}`);
  if (trojan && security === "none") throw new Error("Trojan requires TLS");
  const hasRealityParameters = params.has("pbk") || params.has("sid") || params.has("spx");
  if (security === "none" && hasRealityParameters) throw new Error("Reality parameters conflict with security=none");
  const reality = security === "reality" || hasRealityParameters;
  const tlsEnabled = security === "tls" || reality || trojan;
  if (tlsEnabled) {
    proxy.tls = true;
    const serverName = params.get("sni") || params.get("servername");
    if (serverName) proxy[trojan ? "sni" : "servername"] = serverName;
    const insecure = params.get("allowInsecure") || params.get("insecure");
    if (insecure !== null) proxy["skip-cert-verify"] = booleanValue(insecure);
    const fingerprint = params.get("fp");
    if (fingerprint) proxy["client-fingerprint"] = fingerprint;
    const alpn = alpnValue(params.get("alpn"));
    if (alpn) proxy.alpn = alpn;
  }
  const publicKey = params.get("pbk");
  const spiderX = params.get("spx");
  if (reality && !publicKey) throw new Error("Reality requires a public key");
  if (publicKey) {
    const options: Record<string, unknown> = {
      "public-key": publicKey,
      "short-id": params.get("sid") || "",
    };
    if (spiderX !== null) options["spider-x"] = spiderX;
    proxy["reality-opts"] = options;
  }
}

function parseVlessOrTrojan(uri: string, protocol: "vless" | "trojan"): ClashProxy {
  const parsed = parseCredentialUri(uri);
  const proxy: ClashProxy = {
    name: displayName(parsed.fragment, `${protocol}-${parsed.host}:${parsed.port}`),
    type: protocol,
    server: parsed.host,
    port: parsed.port,
    udp: true,
  };
  if (protocol === "vless") {
    proxy.uuid = parsed.credential;
    const flow = parsed.params.get("flow");
    if (flow) proxy.flow = flow;
    const packetEncoding = parsed.params.get("packetEncoding") ?? parsed.params.get("packet-encoding");
    if (packetEncoding !== null) {
      const normalized = packetEncoding.trim().toLowerCase();
      if (normalized !== "xudp" && normalized !== "packetaddr") {
        throw new Error(`unsupported VLESS packet encoding: ${packetEncoding}`);
      }
      proxy["packet-encoding"] = normalized;
    }
  } else {
    proxy.password = parsed.credential;
    if (parsed.params.has("packetEncoding") || parsed.params.has("packet-encoding")) {
      throw new Error("Trojan packet encoding is not representable in Clash");
    }
  }
  if (parsed.params.has("ech") || parsed.params.has("fm")) {
    throw new Error("ECH/fm options are not representable in Clash");
  }
  const network = (parsed.params.get("type") || parsed.params.get("network") || "tcp").toLowerCase();
  if (network === "grpc") {
    const mode = (parsed.params.get("mode") || "").trim().toLowerCase();
    if (mode && mode !== "gun") throw new Error(`unsupported gRPC mode: ${mode}`);
    if ((parsed.params.get("authority") || parsed.params.get("host") || "").trim()) {
      throw new Error("gRPC authority is not representable in Clash");
    }
  }
  let transportMode = parsed.params.get("mode");
  if (network === "xhttp" || network === "splithttp") {
    const normalizedMode = (transportMode || "").trim().toLowerCase();
    transportMode = normalizedMode && normalizedMode !== "none" ? normalizedMode : "auto";
    if (!["auto", "packet-up", "stream-up", "stream-one"].includes(transportMode)) {
      throw new Error(`unsupported XHTTP mode: ${transportMode}`);
    }
  }
  applyTransport(
    proxy,
    parsed.params.get("type") || parsed.params.get("network"),
    parsed.params.get("path"),
    parsed.params.get("host"),
    parsed.params.get("serviceName") || parsed.params.get("service_name"),
    parsed.params.get("ed"),
    parsed.params.get("eh"),
    transportMode
  );
  applyUrlTls(proxy, parsed.params, protocol === "trojan");
  return proxy;
}

function parseSsPlugin(params: URLSearchParams, proxy: Record<string, unknown>): void {
  const pluginValue = params.get("plugin");
  if (!pluginValue) return;
  const [plugin, ...parts] = pluginValue.split(";");
  if (!plugin) return;
  proxy.plugin = plugin;
  const options: Record<string, unknown> = {};
  for (const part of parts) {
    const separator = part.indexOf("=");
    const key = separator >= 0 ? part.slice(0, separator) : part;
    const value = separator >= 0 ? part.slice(separator + 1) : "true";
    if (!key) continue;
    if (key === "tls" || key === "mux" || key === "fast-open") {
      options[key] = booleanValue(value);
    } else if (key === "obfs") {
      options.mode = value;
    } else {
      options[key] = value;
    }
  }
  if (Object.keys(options).length > 0) proxy["plugin-opts"] = options;
}

function parseSs(uri: string): ClashProxy {
  const hashAt = uri.indexOf("#");
  const fragment = hashAt >= 0 ? uri.slice(hashAt + 1) : "";
  const withoutFragment = hashAt >= 0 ? uri.slice(0, hashAt) : uri;
  const body = withoutFragment.slice("ss://".length);
  let userInfo: string;
  let endpoint: string;
  const at = body.lastIndexOf("@");
  if (at >= 0) {
    userInfo = decodeComponent(body.slice(0, at));
    endpoint = body.slice(at + 1);
    if (!userInfo.includes(":")) userInfo = decodeBase64Utf8(userInfo);
  } else {
    const queryAt = body.indexOf("?");
    const encoded = queryAt >= 0 ? body.slice(0, queryAt) : body;
    const decoded = decodeBase64Utf8(decodeComponent(encoded));
    const decodedAt = decoded.lastIndexOf("@");
    if (decodedAt < 0) throw new Error("invalid legacy ss URI");
    userInfo = decoded.slice(0, decodedAt);
    endpoint = `${decoded.slice(decodedAt + 1)}${queryAt >= 0 ? body.slice(queryAt) : ""}`;
  }
  const separator = userInfo.indexOf(":");
  if (separator <= 0) throw new Error("ss is missing cipher or password");
  const method = decodeComponent(userInfo.slice(0, separator));
  const password = decodeComponent(userInfo.slice(separator + 1));
  // The synthetic scheme must retain explicit default ports such as `:80`.
  const parsed = new URL(`proxy://x@${endpoint}`);
  const host = stripIpv6Brackets(parsed.hostname);
  const port = requiredPort(parsed.port);
  if (!host || !method || !password) throw new Error("ss is missing host, cipher, or password");
  const proxy: ClashProxy = {
    name: displayName(fragment, `ss-${host}:${port}`),
    type: "ss",
    server: host,
    port,
    cipher: method,
    password,
    udp: true,
  };
  parseSsPlugin(parsed.searchParams, proxy);
  return proxy;
}

function parseHysteria2(uri: string): ClashProxy {
  const parsed = parseCredentialUri(uri);
  const security = (parsed.params.get("security") || "tls").toLowerCase();
  if (security !== "tls") throw new Error(`unsupported Hysteria2 security: ${security}`);
  const proxy: ClashProxy = {
    name: displayName(parsed.fragment, `hysteria2-${parsed.host}:${parsed.port}`),
    type: "hysteria2",
    server: parsed.host,
    port: parsed.port,
    password: parsed.credential,
  };
  const sni = parsed.params.get("sni");
  if (sni) proxy.sni = sni;
  const alpn = alpnValue(parsed.params.get("alpn"));
  if (alpn) proxy.alpn = alpn;
  const insecure = parsed.params.get("insecure");
  if (insecure !== null) proxy["skip-cert-verify"] = booleanValue(insecure);
  const obfs = parsed.params.get("obfs");
  if (obfs) proxy.obfs = obfs;
  const obfsPassword = parsed.params.get("obfs-password") || parsed.params.get("obfsPassword");
  if (obfsPassword) proxy["obfs-password"] = obfsPassword;
  return proxy;
}

function decodeSsrParameter(params: URLSearchParams, name: string): string | undefined {
  if (!params.has(name)) return undefined;
  const encoded = params.get(name) || "";
  if (!encoded) return undefined;
  return decodeBase64Utf8(encoded);
}

function parseSsr(uri: string): ClashProxy {
  const encoded = decodeComponent(uri.slice("ssr://".length).split("#", 1)[0]);
  const decoded = decodeBase64Utf8(encoded);
  const queryAt = decoded.indexOf("/?");
  const head = (queryAt >= 0 ? decoded.slice(0, queryAt) : decoded).replace(/\/$/, "");
  const params = new URLSearchParams(queryAt >= 0 ? decoded.slice(queryAt + 2) : "");
  const parts = head.split(":");
  if (parts.length < 6) throw new Error("invalid SSR URI");
  const passwordEncoded = parts.pop() || "";
  const obfs = parts.pop() || "";
  const method = parts.pop() || "";
  const protocol = parts.pop() || "";
  const port = requiredPort(parts.pop());
  const host = stripIpv6Brackets(parts.join(":"));
  const password = decodeBase64Utf8(passwordEncoded);
  if (!host || !protocol || !method || !obfs || !password) throw new Error("SSR is missing connection fields");
  const proxy: ClashProxy = {
    name: decodeSsrParameter(params, "remarks") || `ssr-${host}:${port}`,
    type: "ssr",
    server: host,
    port,
    cipher: method,
    password,
    protocol,
    obfs,
    udp: true,
  };
  const protocolParam = decodeSsrParameter(params, "protoparam");
  const obfsParam = decodeSsrParameter(params, "obfsparam");
  if (protocolParam) proxy["protocol-param"] = protocolParam;
  if (obfsParam) proxy["obfs-param"] = obfsParam;
  return proxy;
}

function firstParameter(params: URLSearchParams, ...names: string[]): string | null {
  for (const name of names) {
    const value = params.get(name);
    if (value !== null) return value;
  }
  return null;
}

function parseTuic(uri: string): ClashProxy {
  const parsed = new URL(uri);
  const host = stripIpv6Brackets(parsed.hostname);
  const port = requiredPort(parsed.port);
  const uuid = decodeComponent(parsed.username) || parsed.searchParams.get("uuid") || "";
  const password = decodeComponent(parsed.password) || parsed.searchParams.get("password") || "";
  if (!host || !uuid || !password) throw new Error("TUIC is missing host, UUID, or password");
  const security = (parsed.searchParams.get("security") || "tls").toLowerCase();
  if (security !== "tls") throw new Error(`unsupported TUIC security: ${security}`);
  const proxy: ClashProxy = {
    name: displayName(parsed.hash.slice(1), `tuic-${host}:${port}`),
    type: "tuic",
    server: host,
    port,
    uuid,
    password,
    udp: true,
  };
  const sni = firstParameter(parsed.searchParams, "sni", "peer", "server_name");
  if (sni) proxy.sni = sni;
  const insecure = firstParameter(parsed.searchParams, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify");
  if (insecure !== null) proxy["skip-cert-verify"] = booleanValue(insecure);
  const alpn = alpnValue(parsed.searchParams.get("alpn"));
  if (alpn) proxy.alpn = alpn;
  const fingerprint = firstParameter(parsed.searchParams, "fp", "fingerprint");
  if (fingerprint) proxy["client-fingerprint"] = fingerprint;
  const congestion = firstParameter(parsed.searchParams, "congestion_control", "congestion-controller");
  if (congestion) proxy["congestion-controller"] = congestion;
  const relayMode = firstParameter(parsed.searchParams, "udp_relay_mode", "udp-relay-mode");
  if (relayMode) proxy["udp-relay-mode"] = relayMode;
  return proxy;
}

export function uriToClashProxy(uri: string, index = 0): ClashProxy | null {
  try {
    const match = uri.match(/^([a-z0-9]+):\/\//i);
    if (!match) return null;
    const protocol = match[1].toLowerCase();
    if (protocol === "vmess") return parseVmess(uri, index);
    if (protocol === "vless" || protocol === "trojan") return parseVlessOrTrojan(uri, protocol);
    if (protocol === "ss") return parseSs(uri);
    if (protocol === "ssr") return parseSsr(uri);
    if (protocol === "hysteria2" || protocol === "hysteria" || protocol === "hy2") return parseHysteria2(uri);
    if (protocol === "tuic") return parseTuic(uri);
    return null;
  } catch {
    return null;
  }
}

export function uniqueProxyNames(proxies: ClashProxy[]): ClashProxy[] {
  const used = new Set<string>();
  return proxies.map((proxy) => {
    const base = String(proxy.name || "proxy");
    let name = base;
    let suffix = 2;
    while (used.has(name)) {
      name = `${base} [${suffix}]`;
      suffix += 1;
    }
    used.add(name);
    return { ...proxy, name };
  });
}

export function renderClashYaml(uris: string[]): string {
  const proxies = uniqueProxyNames(
    uris.map((uri, index) => {
      const proxy = uriToClashProxy(uri, index);
      if (!proxy) throw new Error(`URI at index ${index} cannot be rendered as Clash`);
      return proxy;
    })
  );
  return stringify({ proxies }, { lineWidth: 0, aliasDuplicateObjects: false });
}
