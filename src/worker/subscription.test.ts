import { describe, expect, it } from "vitest";
import { parse, parseDocument } from "yaml";

import {
  decodeBase64Utf8,
  encodeBase64Utf8,
  renderClashYaml,
  uriToClashProxy,
} from "./subscription";

function urlSafeBase64(value: string): string {
  return encodeBase64Utf8(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("base64 helpers", () => {
  it("round-trips UTF-8 and accepts unpadded URL-safe input", () => {
    const value = "vmess://example-\u53f0\u7063";
    expect(decodeBase64Utf8(urlSafeBase64(value))).toBe(value);
  });

  it("rejects malformed base64", () => {
    expect(() => decodeBase64Utf8("not base64!")) .toThrow("invalid base64");
  });
});

describe("URI to Clash conversion", () => {
  it("places VLESS WebSocket and Reality settings in Clash-native fields", () => {
    const proxy = uriToClashProxy(
      "vless://user-id@example.com:443?security=reality&type=ws&path=%2Fws%3Fed%3D2048&host=edge.example&" +
      "sni=origin.example&fp=chrome&pbk=public-key&sid=abcd&flow=xtls-rprx-vision#shared"
    );
    expect(proxy).toMatchObject({
      name: "shared",
      type: "vless",
      server: "example.com",
      port: 443,
      uuid: "user-id",
      flow: "xtls-rprx-vision",
      network: "ws",
      tls: true,
      servername: "origin.example",
      "client-fingerprint": "chrome",
      "ws-opts": { path: "/ws?ed=2048", headers: { Host: "edge.example" } },
      "reality-opts": { "public-key": "public-key", "short-id": "abcd" },
    });
    expect(proxy).not.toHaveProperty("path");
  });

  it("maps VLESS packet encoding and Reality spider-x while accepting the default gRPC mode", () => {
    expect(uriToClashProxy(
      "vless://user-id@example.com:443?security=reality&type=grpc&serviceName=proxy&mode=gun&authority=&" +
      "packetEncoding=xudp&pbk=public-key&sid=abcd&spx=%2Fspider#grpc-reality"
    )).toMatchObject({
      type: "vless",
      network: "grpc",
      "packet-encoding": "xudp",
      "grpc-opts": { "grpc-service-name": "proxy" },
      "reality-opts": {
        "public-key": "public-key",
        "short-id": "abcd",
        "spider-x": "/spider",
      },
    });
  });

  it("drops VLESS gRPC options that the Clash renderer cannot preserve", () => {
    expect(uriToClashProxy(
      "vless://id@example.com:443?type=grpc&serviceName=proxy&mode=multi#multi"
    )).toBeNull();
    expect(uriToClashProxy(
      "vless://id@example.com:443?type=grpc&serviceName=proxy&mode=gun&authority=origin.example#authority"
    )).toBeNull();
  });

  it("drops unsupported VLESS ECH, fm, and packet-encoding options", () => {
    expect(uriToClashProxy("vless://id@example.com:443?security=tls&ech=config#ech")).toBeNull();
    expect(uriToClashProxy("vless://id@example.com:443?security=tls&fm=1#fm")).toBeNull();
    expect(uriToClashProxy(
      "vless://id@example.com:443?security=tls&packetEncoding=unknown#packet"
    )).toBeNull();
  });

  it("rejects unsupported or downgraded URL security modes", () => {
    expect(uriToClashProxy("vless://id@example.com:443?security=bogus#bad")).toBeNull();
    expect(uriToClashProxy("trojan://secret@example.com:443?security=none#plain")).toBeNull();
    expect(uriToClashProxy("hysteria2://secret@example.com:443?security=none#plain")).toBeNull();
    expect(uriToClashProxy("vless://id@example.com:443?security=reality#no-key")).toBeNull();
  });

  it("preserves VMess gRPC, TLS, SNI, cipher, and ALPN parameters", () => {
    const vmess = {
      v: "2",
      ps: "quoted: name",
      add: "vm.example",
      port: "8443",
      id: "uuid",
      aid: "0",
      scy: "chacha20-poly1305",
      net: "grpc",
      serviceName: "proxy-service",
      tls: "tls",
      sni: "tls.example",
      alpn: "h2,http/1.1",
      fp: "chrome",
    };
    expect(uriToClashProxy(`vmess://${urlSafeBase64(JSON.stringify(vmess))}`)).toMatchObject({
      type: "vmess",
      server: "vm.example",
      port: 8443,
      cipher: "chacha20-poly1305",
      network: "grpc",
      tls: true,
      servername: "tls.example",
      alpn: ["h2", "http/1.1"],
      "grpc-opts": { "grpc-service-name": "proxy-service" },
    });
  });

  it("maps VMess gRPC path, XHTTP mode, and legacy TCP+HTTP header transport", () => {
    const grpc = { add: "grpc.example", port: "443", id: "uuid", net: "grpc", path: "tunnel", type: "gun" };
    expect(uriToClashProxy(`vmess://${urlSafeBase64(JSON.stringify(grpc))}`)).toMatchObject({
      network: "grpc",
      "grpc-opts": { "grpc-service-name": "tunnel" },
    });

    const xhttp = {
      add: "xhttp.example", port: "443", id: "uuid", net: "xhttp", type: "packet-up", path: "/x", host: "cdn.example",
    };
    expect(uriToClashProxy(`vmess://${urlSafeBase64(JSON.stringify(xhttp))}`)).toMatchObject({
      network: "xhttp",
      "xhttp-opts": { path: "/x", host: "cdn.example", mode: "packet-up" },
    });

    const http = { add: "http.example", port: "80", id: "uuid", net: "tcp", type: "http", path: "/h", host: "origin.example" };
    expect(uriToClashProxy(`vmess://${urlSafeBase64(JSON.stringify(http))}`)).toMatchObject({
      network: "http",
      "http-opts": { method: "GET", path: ["/h"], headers: { Host: ["origin.example"] } },
    });
  });

  it("decodes SIP002 SS credentials, IPv6, and plugin options", () => {
    const credential = urlSafeBase64("chacha20-ietf-poly1305:p@ss:word");
    const proxy = uriToClashProxy(
      `ss://${credential}@[2001:db8::1]:8388?plugin=v2ray-plugin%3Bobfs%3Dwebsocket%3Bhost%3Dcdn.example%3Btls#node`
    );
    expect(proxy).toMatchObject({
      type: "ss",
      server: "2001:db8::1",
      port: 8388,
      cipher: "chacha20-ietf-poly1305",
      password: "p@ss:word",
      plugin: "v2ray-plugin",
      "plugin-opts": { mode: "websocket", host: "cdn.example", tls: true },
    });
  });

  it("converts ShadowsocksR credentials and protocol/obfs parameters", () => {
    const password = urlSafeBase64("p@ssword");
    const head = "ssr.example:8388:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:" + password;
    const query = "remarks=" + urlSafeBase64("SSR node") +
      "&protoparam=" + urlSafeBase64("proto:value") +
      "&obfsparam=" + urlSafeBase64("cdn.example");
    expect(uriToClashProxy(`ssr://${urlSafeBase64(`${head}/?${query}`)}`)).toMatchObject({
      name: "SSR node",
      type: "ssr",
      server: "ssr.example",
      port: 8388,
      cipher: "aes-256-cfb",
      password: "p@ssword",
      protocol: "auth_sha1_v4",
      obfs: "tls1.2_ticket_auth",
      "protocol-param": "proto:value",
      "obfs-param": "cdn.example",
    });
  });

  it("converts TUIC credentials and Mihomo connection parameters", () => {
    expect(uriToClashProxy(
      "tuic://user-id:p%40ss@host.example:443?security=tls&sni=tls.example&alpn=h3&fp=chrome&" +
      "congestion_control=bbr&udp_relay_mode=native&allowInsecure=1#tuic-node"
    )).toMatchObject({
      name: "tuic-node",
      type: "tuic",
      server: "host.example",
      port: 443,
      uuid: "user-id",
      password: "p@ss",
      sni: "tls.example",
      alpn: ["h3"],
      "client-fingerprint": "chrome",
      "congestion-controller": "bbr",
      "udp-relay-mode": "native",
      "skip-cert-verify": true,
    });
  });

  it("converts Hysteria2-specific parameters", () => {
    expect(uriToClashProxy(
      "hysteria2://secret@example.com:443?sni=tls.example&insecure=1&obfs=salamander&obfs-password=mask#hy2"
    )).toMatchObject({
      type: "hysteria2",
      password: "secret",
      sni: "tls.example",
      "skip-cert-verify": true,
      obfs: "salamander",
      "obfs-password": "mask",
    });
  });

  it("preserves XHTTP and HTTPUpgrade options instead of dropping transport fields", () => {
    expect(uriToClashProxy(
      "vless://one@xhttp.example:443?security=tls&type=xhttp&path=%2Fx&host=cdn.example#xhttp"
    )).toMatchObject({
      network: "xhttp",
      "xhttp-opts": { path: "/x", host: "cdn.example" },
    });
    expect(uriToClashProxy(
      "vless://two@upgrade.example:443?security=tls&type=http-upgrade&path=%2Fu&host=edge.example#upgrade"
    )).toMatchObject({
      network: "httpupgrade",
      "http-upgrade-opts": { path: "/u", host: "edge.example" },
    });
  });

  it("drops unsupported transports rather than emitting a misleading proxy", () => {
    expect(uriToClashProxy("vless://id@example.com:443?type=made-up#bad")).toBeNull();
  });

  it("normalizes the VMess raw transport alias to TCP", () => {
    const vmess = { add: "raw.example", port: "443", id: "uuid", net: "raw" };
    expect(uriToClashProxy(`vmess://${urlSafeBase64(JSON.stringify(vmess))}`)).toMatchObject({
      network: "tcp",
    });
  });
});

describe("Clash YAML rendering", () => {
  it("emits parseable YAML with globally unique names and string-safe values", () => {
    const first = "trojan://00123@one.example:443?security=tls&sni=tls.example#same%3Aname";
    const second = "trojan://yes@two.example:443?security=tls&sni=tls.example#same%3Aname";
    const document = parse(renderClashYaml([first, second])) as { proxies: Array<Record<string, unknown>> };
    expect(document.proxies.map((proxy) => proxy.name)).toEqual(["same:name", "same:name [2]"]);
    expect(document.proxies.map((proxy) => proxy.password)).toEqual(["00123", "yes"]);
    expect(new Set(document.proxies.map((proxy) => proxy.name)).size).toBe(2);
  });

  it("escapes backslashes for strict YAML parsers", () => {
    const uri =
      "vless://id@example.com:443?security=tls&type=ws&" +
      "path=%2Fws%3Fed%5C%3D2560&host=edge.example#node%3A%20%5Cq";
    const rendered = renderClashYaml([uri]);
    expect(parseDocument(rendered).errors).toHaveLength(0);
    const document = parse(rendered) as { proxies: Array<Record<string, unknown>> };

    expect(document.proxies[0].name).toBe("node: \\q");
    expect(document.proxies[0]["ws-opts"]).toEqual({
      path: "/ws?ed\\=2560",
      headers: { Host: "edge.example" },
    });
  });

  it("fails closed instead of silently omitting an unsupported URI", () => {
    expect(() => renderClashYaml(["unknown://credential@example.com:443"])).toThrow("cannot be rendered");
  });
});
