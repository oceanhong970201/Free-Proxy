"""Per-scheme proxy URI / subscription parser (Stage 1 + 4).

Dispatcher:
  - vmess  : base64-decode raw[8:] + JSON parse (pad ===)
  - vless/trojan/tuic/hysteria2/hy2/ss/ssr : URI querystring parse
  - clash YAML  : PyYAML `proxies:` segment
  - sing-box JSON : `outbounds[]`

Unified raw-text regex (yaney01 pattern, PRD 4.1):
  (?<![\\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\\s<>#]+)
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import unquote, urlparse, parse_qs, urlencode, quote

import yaml

from .models import ProxyNode

# PRD §4.1 unified regex
CONFIG_RE = re.compile(
    r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>#]+)",
    re.IGNORECASE,
)


def node_to_uri(n: ProxyNode) -> str:
    """Rebuild a canonical URI from ProxyNode fields.

    Used when the source is clash YAML / sing-box JSON (no original URI) so the
    emitted v2ray-base64 subscription contains real vmess://... / vless://...
    URIs rather than clash JSON object dumps. Best-effort — missing fields
    produce a minimal-but-valid URI.
    """
    proto = (n.proto or "").lower()
    host = n.host or ""
    port = n.port or 0
    name = n.name or ""

    if proto == "vmess":
        obj = {
            "v": "2",
            "ps": name,
            "add": host,
            "port": str(port),
            "id": n.uuid or "",
            "aid": "0",
            "net": n.net or "tcp",
            "type": "none",
            "host": n.host_header or "",
            "path": n.path or "",
            "tls": "tls" if (n.sni or n.flow) else "",
            "sni": n.sni or "",
        }
        b = base64.b64encode(
            json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        return f"vmess://{b}"

    # querystring-style URIs
    userinfo = n.uuid or n.password or ""
    if proto == "ss":
        # SIP002: ss://base64(method:password)@host:port
        method = n.method or "aes-256-gcm"
        pwd = n.password or ""
        cred_blob = base64.b64encode(f"{method}:{pwd}".encode("utf-8")).decode("ascii")
        cred = quote(cred_blob, safe="")
        qs = {}
        if n.name:
            qs["name"] = n.name
        qstr = urlencode(qs)
        return f"ss://{cred}@{host}:{port}#{quote(name)}"

    # vless / trojan / tuic / hysteria2 / hy2
    qs = {}
    if n.sni:
        qs["sni"] = n.sni
    if n.net:
        qs["type"] = n.net
    if n.path:
        qs["path"] = quote(n.path, safe="")
    if n.host_header:
        qs["host"] = n.host_header
    if n.flow:
        qs["flow"] = n.flow
    if n.fp:
        qs["fp"] = n.fp
    if n.alpn:
        qs["alpn"] = n.alpn
    if n.pbk:
        qs["pbk"] = n.pbk
    if n.sid:
        qs["sid"] = n.sid
    if n.skip_cert_verify:
        qs["allowInsecure"] = "1"
    if n.sni or n.flow or n.pbk:
        qs["security"] = "tls"
    qstr = urlencode(qs, quote_via=quote)
    frag = quote(name) if name else ""
    return (
        f"{proto}://{userinfo}@{host}:{port}?{qstr}#{frag}"
        if qstr
        else f"{proto}://{userinfo}@{host}:{port}#{frag}"
    )


def _b64decode_loose(s: str) -> str:
    """base64 decode with missing padding tolerated."""
    s = s.strip()
    # url-safe variants
    s = s.replace("-", "+").replace("_", "/")
    pad = "=" * (-len(s) % 4)
    s += pad
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "ignore")
    except Exception:
        return ""


def extract_uris(text: str) -> list[str]:
    """Pull all proxy URIs from a raw blob of text."""
    if not text:
        return []
    out = []
    for m in CONFIG_RE.finditer(text):
        uri = m.group(1).strip().rstrip(",;\"'")
        if uri:
            out.append(uri)
    return out


def _parse_vmess(uri: str) -> ProxyNode | None:
    # vmess://<base64-json>
    body = uri[len("vmess://") :]
    raw_json = _b64decode_loose(body)
    if not raw_json:
        return None
    try:
        d = json.loads(raw_json)
    except Exception:
        return None
    try:
        port = int(d.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    host = str(d.get("add") or d.get("host") or "")
    if not host or port <= 0:
        return None
    return ProxyNode(
        proto="vmess",
        host=host,
        port=port,
        uuid=str(d.get("id") or "") or None,
        method=str(d.get("scy") or d.get("method") or "auto") or None,
        sni=str(d.get("sni") or "") or None,
        net=str(d.get("net") or d.get("type") or "") or None,
        path=str(d.get("path") or "") or None,
        host_header=str(d.get("host") or "") or None,
        flow=None,
        fp=None,
        alpn=str(d.get("alpn") or "") or None,
        pbk=None,
        sid=None,
        raw=uri,
        name=str(d.get("ps") or "") or None,
    )


def _parse_query_uri(uri: str, proto: str) -> ProxyNode | None:
    # proto://cred@host:port?params#name   (vless/trojan/tuic/hy2/ss/ssr)
    try:
        parsed = urlparse(uri)
    except Exception:
        return None
    host = parsed.hostname or ""
    try:
        port = parsed.port or 0
    except (ValueError, TypeError):
        port = 0
    if not host or port <= 0:
        return None
    # Reconstruct the full userinfo. urlparse splits userinfo on the first ':'
    # into username/password — for SIP002 "method:password" (ss/ssr) or any
    # credential containing a ':' we must rejoin them.
    _user = unquote(parsed.username or "")
    _pass = unquote(parsed.password or "") if parsed.password is not None else ""
    if parsed.password is not None:
        cred = f"{_user}:{_pass}"
    else:
        cred = _user
    name = unquote(parsed.fragment) if parsed.fragment else None
    q = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}

    node = ProxyNode(
        proto=proto,
        host=host,
        port=port,
        raw=uri,
        name=name,
    )

    # SIP002 userinfo handling for ss/ssr.
    # SIP002 allows two userinfo forms:
    #   1. plain  "method:password"            (contains ':')
    #   2. base64 "base64(method:password)"   (no ':', matches ^[A-Za-z0-9+/=_-]+$)
    # The base64 form MUST be decoded, otherwise the whole blob is stored as
    # the password and the cipher (method) is lost. (audit M1)
    ss_method: str | None = None
    ss_password: str | None = None
    if proto in ("ss", "ssr"):
        if cred and ":" in cred:
            # plain method:password
            mp = cred.split(":", 1)
            ss_method = mp[0] or None
            ss_password = mp[1] if len(mp) > 1 else None
        elif cred and re.fullmatch(r"[A-Za-z0-9+/=_-]+", cred):
            # base64(method:password) — decode then split
            decoded = _b64decode_loose(cred)
            if decoded and ":" in decoded:
                mp = decoded.split(":", 1)
                ss_method = mp[0] or None
                ss_password = mp[1] if len(mp) > 1 else None
            else:
                # decoded but no ':' — treat whole as password, no method
                ss_password = decoded or cred or None
        else:
            ss_password = cred or None

    # credential distribution per protocol
    if proto in ("vless", "trojan"):
        node.uuid = cred or None
        node.password = cred or None
    elif proto in ("tuic",):
        node.uuid = cred or q.get("uuid") or None
        node.password = q.get("password") or None
    elif proto in ("hysteria2", "hysteria", "hy2"):
        node.password = cred or q.get("password") or None
    elif proto in ("ss", "ssr"):
        node.password = ss_password
        node.method = ss_method or q.get("method") or q.get("cipher") or None

    node.sni = q.get("sni") or q.get("peer") or None
    node.net = q.get("type") or q.get("network") or None
    node.path = q.get("path") or None
    node.host_header = q.get("host") or q.get("headerHost") or None
    node.flow = q.get("flow") or None
    node.fp = q.get("fp") or None
    node.alpn = q.get("alpn") or None
    node.pbk = q.get("pbk") or q.get("public-key") or None
    node.sid = q.get("sid") or q.get("short-id") or None
    # allowInsecure=1 / true -> self-signed cert tolerated (clash skip-cert-verify)
    ai = (q.get("allowInsecure") or q.get("allowinsecure") or "").lower()
    node.skip_cert_verify = True if ai in ("1", "true") else None
    return node


def parse_uri(uri: str) -> ProxyNode | None:
    uri = uri.strip()
    low = uri.lower()
    if low.startswith("vmess://"):
        return _parse_vmess(uri)
    for p in (
        "vless",
        "trojan",
        "tuic",
        "hysteria2",
        "hysteria",
        "hy2",
        "ss",
        "ssr",
        "juicity",
    ):
        if low.startswith(f"{p}://"):
            return _parse_query_uri(uri, "hysteria2" if p in ("hy2", "hysteria") else p)
    return None


def parse_clash_yaml(text: str) -> list[ProxyNode]:
    """Read `proxies:` segment of a clash YAML config."""
    try:
        doc = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies") or []
    nodes: list[ProxyNode] = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        proto = str(p.get("type") or "").lower()
        host = str(p.get("server") or "")
        try:
            port = int(p.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or port <= 0:
            continue
        # normalize clash proto -> our proto
        if proto == "hysteria":
            proto_n = "hysteria2"
        elif proto in (
            "vmess",
            "vless",
            "trojan",
            "tuic",
            "hysteria2",
            "ss",
            "ssr",
            "juicity",
        ):
            proto_n = proto
        else:
            continue
        node = ProxyNode(
            proto=proto_n,
            host=host,
            port=port,
            uuid=str(p.get("uuid") or "") or None,
            password=str(p.get("password") or "") or None,
            method=str(p.get("cipher") or p.get("method") or "") or None,
            sni=str(p.get("sni") or p.get("peer") or "") or None,
            net=str(p.get("network") or p.get("net") or "") or None,
            path=str(p.get("path") or "") or None,
            host_header=(
                str(p.get("headers", {}).get("Host") or "")
                if isinstance(p.get("headers"), dict)
                else None
            ),
            flow=str(p.get("flow") or "") or None,
            fp=str(p.get("client-fingerprint") or "") or None,
            alpn=str(p.get("alpn") or "") or None,
            pbk=(
                str(p.get("reality-opts", {}).get("public-key") or "")
                if isinstance(p.get("reality-opts"), dict)
                else None
            ),
            sid=(
                str(p.get("reality-opts", {}).get("short-id") or "")
                if isinstance(p.get("reality-opts"), dict)
                else None
            ),
            name=str(p.get("name") or "") or None,
            raw="",  # filled below
        )
        node.raw = node_to_uri(node)
        nodes.append(node)
    return nodes


def parse_singbox_json(text: str) -> list[ProxyNode]:
    """Read `outbounds[]` from a sing-box JSON config."""
    try:
        doc = json.loads(text)
    except Exception:
        return []
    outbounds = doc.get("outbounds") if isinstance(doc, dict) else doc
    if not isinstance(outbounds, list):
        return []
    nodes: list[ProxyNode] = []
    for o in outbounds:
        if not isinstance(o, dict):
            continue
        proto = str(o.get("type") or "").lower()
        host = str(o.get("server") or "")
        try:
            port = int(o.get("server_port") or o.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or port <= 0:
            continue
        # sing-box type -> our proto
        proto_map = {
            "vmess": "vmess",
            "vless": "vless",
            "trojan": "trojan",
            "tuic": "tuic",
            "hysteria2": "hysteria2",
            "hysteria": "hysteria2",
            "shadowsocks": "ss",
            "shadowtls": "ss",
        }
        proto_n = proto_map.get(proto)
        if not proto_n:
            continue
        tls = o.get("tls") if isinstance(o.get("tls"), dict) else {}
        node = ProxyNode(
            proto=proto_n,
            host=host,
            port=port,
            uuid=str(o.get("uuid") or "") or None,
            password=str(o.get("password") or "") or None,
            method=str(o.get("method") or "") or None,
            sni=str(tls.get("server_name") or "") or None,
            net=str(o.get("network") or "") or None,
            path=(
                str(o.get("transport", {}).get("path") or "")
                if isinstance(o.get("transport"), dict)
                else None
            ),
            host_header=(
                str(o.get("transport", {}).get("headers", {}).get("Host") or "")
                if isinstance(o.get("transport"), dict)
                else None
            ),
            flow=str(o.get("flow") or "") or None,
            fp=(
                str(tls.get("utls", {}).get("fingerprint") or "")
                if isinstance(tls.get("utls"), dict)
                else None
            ),
            alpn=str(tls.get("alpn") or "") or None,
            pbk=(
                str(tls.get("reality", {}).get("public_key") or "")
                if isinstance(tls.get("reality"), dict)
                else None
            ),
            sid=(
                str(tls.get("reality", {}).get("short_id") or "")
                if isinstance(tls.get("reality"), dict)
                else None
            ),
            name=str(o.get("tag") or "") or None,
            raw="",  # filled below
        )
        node.raw = node_to_uri(node)
        nodes.append(node)
    return nodes


def parse_v2ray_base64(text: str) -> list[ProxyNode]:
    """v2ray base64 subscription: whole blob or per-line b64 of URIs."""
    nodes: list[ProxyNode] = []
    if not text:
        return nodes
    # try whole-blob decode first
    decoded = _b64decode_loose(text.strip())
    candidates = [decoded] if decoded else []
    # also try line-by-line
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        d = _b64decode_loose(line)
        if d and "://" in d:
            candidates.append(d)
        elif "://" in line:
            candidates.append(line)
    seen = set()
    for c in candidates:
        for uri in extract_uris(c):
            if uri in seen:
                continue
            seen.add(uri)
            n = parse_uri(uri)
            if n:
                nodes.append(n)
    return nodes


def parse_raw(source_format: str, text: str) -> list[ProxyNode]:
    """Dispatcher: format -> parse function.

    source_format is the `format` field from sources.json:
    clash | singbox | v2ray | vpnsuper | (auto/raw fallback: regex on raw text).
    """
    fmt = (source_format or "").lower()
    if fmt in ("clash", "clash.yaml", "yaml"):
        nodes = parse_clash_yaml(text)
        # some clash YAMLs also embed URIs in comments; regex fallback adds any stragglers
        for uri in extract_uris(text):
            n = parse_uri(uri)
            if n and n.raw not in {x.raw for x in nodes}:
                nodes.append(n)
        return nodes
    if fmt in ("singbox", "sing-box", "json"):
        return parse_singbox_json(text)
    if fmt in ("v2ray", "v2ray-base64", "base64"):
        return parse_v2ray_base64(text)
    if fmt == "vpnsuper":
        # vpnsuper raw is a newline-separated list of trojan:// URIs (already
        # built by vpnsuper_feed from the decrypted server lists). Same regex
        # extraction as the raw fallback, but explicit so it doesn't waste a
        # base64-decode pass.
        out: list[ProxyNode] = []
        seen: set[str] = set()
        for uri in extract_uris(text):
            if uri in seen:
                continue
            seen.add(uri)
            n = parse_uri(uri)
            if n:
                out.append(n)
        return out
    # raw / unknown -> regex on text
    out = []
    seen = set()
    for uri in extract_uris(text):
        if uri in seen:
            continue
        seen.add(uri)
        n = parse_uri(uri)
        if n:
            out.append(n)
    return out
