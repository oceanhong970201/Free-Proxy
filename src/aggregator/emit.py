"""Emit live.jsonl -> output/{clash.yaml, singbox.json, v2ray-base64.txt, feed.xml}.

Stage 1 output layer.

Filtering & sort policy (per _QUALITY_SPEC.md):
  - Only emit alive nodes. Nodes explicitly marked alive=False (dead) are
    dropped. Nodes with alive=None (unverified — e.g. clash-speedtest binary
    unavailable, or verify stage not yet run) are kept so the pipeline never
    blocks on the (stub) verify stage. This satisfies the acceptance criterion:
    "若 D1 都 alive=None 則輸出全部，但不崩".
  - Sort: if any node carries a `download_speed` field (added by agent 1),
    sort by download_speed desc (None last). Otherwise fall back to
    latency_ms asc (None latency treated as large).
  - If zero alive nodes remain, emit empty-but-valid payloads (no crash).

Writes all four formats: clash.yaml, singbox.json, v2ray-base64.txt, feed.xml.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from xml.sax import saxutils

import yaml

from .models import ProxyNode

ROOT = Path(__file__).resolve().parents[2]
LIVE_FILE = ROOT / "state" / "live.jsonl"
OUTPUT_DIR = ROOT / "output"
FEED_FILE = OUTPUT_DIR / "feed.xml"


def load_live_nodes() -> list[ProxyNode]:
    if not LIVE_FILE.exists():
        return []
    nodes: list[ProxyNode] = []
    for line in LIVE_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        try:
            nodes.append(ProxyNode(**d))
        except Exception:
            continue
    return nodes


def _download_speed(n: ProxyNode):
    """Safely read download_speed — field may not exist yet (agent 1 adds it)."""
    return getattr(n, "download_speed", None)


def filter_alive(nodes: list[ProxyNode]) -> list[ProxyNode]:
    """Drop dead nodes (alive is False). Keep alive=True and unverified (None).

    None is kept so the pipeline still emits when verify hasn't run (acceptance:
    "若 D1 都 alive=None 則輸出全部，但不崩").
    """
    return [n for n in nodes if n.alive is not False]


def sort_nodes(nodes: list[ProxyNode]) -> list[ProxyNode]:
    """Sort alive nodes.

    If every node lacks download_speed (field absent / all None), sort by
    latency_ms asc (None latency treated as large). Otherwise sort by
    download_speed desc — None download_speed sorts last (treated as -1).
    """
    has_speed = any(_download_speed(n) is not None for n in nodes)

    def latency_key(n: ProxyNode):
        lat = n.latency_ms if n.latency_ms is not None else 10**9
        return (lat, n.host or "", n.port or 0)

    def speed_key(n: ProxyNode):
        ds = _download_speed(n)
        # None download_speed sorts last (use -1.0 so real speeds come first).
        return (-(ds if ds is not None else -1.0), n.latency_ms or 10**9)

    return sorted(nodes, key=speed_key if has_speed else latency_key)


def select_nodes() -> list[ProxyNode]:
    """Load + filter dead + sort. Single source of truth for emit consumers."""
    return sort_nodes(filter_alive(load_live_nodes()))


def to_clash_dict(n: ProxyNode) -> dict:
    # name uniqueness: clash-speedtest aborts on duplicate proxy names.
    # host:port alone isn't unique (same server, different uuid/proto), so
    # fold proto + uuid/password prefix + host:port into a guaranteed-unique key.
    cred = (n.uuid or n.password or "")[:8]
    d = {
        "name": f"{n.proto}-{cred}-{n.host}:{n.port}",
        "type": n.proto,
        "server": n.host,
        "port": n.port,
        "udp": True,
    }
    if n.uuid:
        d["uuid"] = n.uuid
    if n.password:
        d["password"] = n.password
    if n.method:
        if n.proto == "ss":
            d["cipher"] = n.method
        else:
            d["cipher"] = n.method
    # protocol-required fields so mihomo/clash-speedtest loads cleanly
    if n.proto == "vmess":
        d.setdefault("alterId", 0)
        d.setdefault("cipher", "auto")
        d.setdefault("network", n.net or "tcp")
    elif n.proto == "vless":
        d.setdefault("network", n.net or "tcp")
    elif n.proto == "trojan":
        d.setdefault("network", n.net or "tcp")
        d["password"] = n.password or ""
        if not n.sni:
            d["sni"] = n.host
        d["skip-cert-verify"] = (
            bool(n.skip_cert_verify) if n.skip_cert_verify is not None else False
        )
    elif n.proto in ("hysteria2", "hy2"):
        d["password"] = n.password or ""
        if not n.sni:
            d["sni"] = n.host
    elif n.proto == "ss":
        d.setdefault("cipher", n.method or "aes-256-gcm")
    if n.sni:
        d["sni"] = n.sni
    if n.net and "network" not in d:
        d["network"] = n.net
    if n.path:
        d["path"] = n.path
        d.setdefault("network", "ws")
    if n.host_header:
        d.setdefault("headers", {})["Host"] = n.host_header
    if n.flow:
        d["flow"] = n.flow
        d["tls"] = True
    if n.fp:
        d["client-fingerprint"] = n.fp
    if n.alpn:
        # mihomo requires alpn to be a list (slice); source may store it as a
        # comma-separated string or single value. Normalize to list.
        alpn = n.alpn
        if isinstance(alpn, str):
            d["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        elif isinstance(alpn, list):
            d["alpn"] = alpn
        else:
            d["alpn"] = [str(alpn)]
    if n.pbk:
        d.setdefault("reality-opts", {})["public-key"] = n.pbk
    if n.sid:
        d.setdefault("reality-opts", {})["short-id"] = n.sid
    # tls/skip-cert-verify when sni or reality present
    if (n.sni or n.pbk) and "tls" not in d:
        d["tls"] = True
        if "skip-cert-verify" not in d:
            d["skip-cert-verify"] = (
                bool(n.skip_cert_verify) if n.skip_cert_verify is not None else False
            )
    return d


def to_singbox_outbound(n: ProxyNode) -> dict:
    type_map = {"ss": "shadowsocks", "hysteria2": "hysteria2"}
    o = {
        "type": type_map.get(n.proto, n.proto),
        "tag": n.name or f"{n.proto}-{n.host}-{n.port}",
        "server": n.host,
        "server_port": n.port,
    }
    if n.uuid:
        o["uuid"] = n.uuid
    if n.password:
        o["password"] = n.password
    if n.method and n.proto == "ss":
        o["method"] = n.method
    if n.net:
        o["network"] = n.net
    if n.path:
        o.setdefault("transport", {})["path"] = n.path
    if n.host_header:
        o.setdefault("transport", {}).setdefault("headers", {})["Host"] = n.host_header
    tls = {}
    if n.sni:
        tls["server_name"] = n.sni
    if n.alpn:
        tls["alpn"] = n.alpn
    if n.fp:
        tls.setdefault("utls", {})["fingerprint"] = n.fp
    if n.pbk:
        tls.setdefault("reality", {})["public_key"] = n.pbk
    if n.sid:
        tls.setdefault("reality", {})["short_id"] = n.sid
    if tls:
        o["tls"] = tls
    return o


def emit_clash(nodes: list[ProxyNode]) -> dict:
    proxies = []
    seen_names: set[str] = set()
    for i, n in enumerate(nodes):
        d = to_clash_dict(n)
        base = d["name"]
        name = base
        suffix = 1
        while name in seen_names:
            name = f"{base}-{suffix}"
            suffix += 1
        d["name"] = name
        seen_names.add(name)
        proxies.append(d)
    return {"proxies": proxies}


def emit_singbox(nodes: list[ProxyNode]) -> dict:
    return {"outbounds": [to_singbox_outbound(n) for n in nodes]}


def emit_v2ray_b64(nodes: list[ProxyNode]) -> str:
    uris = [n.raw for n in nodes if n.raw]
    blob = "\n".join(uris)
    return base64.b64encode(blob.encode("utf-8")).decode("ascii")


def _fmt_speed(ds) -> str:
    if ds is None:
        return "n/a"
    try:
        return f"{float(ds):.1f}MB/s"
    except (TypeError, ValueError):
        return "n/a"


def _node_title(n: ProxyNode) -> str:
    base = n.name or f"{n.proto}-{n.host}"
    ds = _download_speed(n)
    return f"{base} - {_fmt_speed(ds)}"


def _node_description(n: ProxyNode) -> str:
    ds = _download_speed(n)
    parts = [
        f"proto={n.proto}",
        f"host={n.host}",
        f"port={n.port}",
        f"latency={n.latency_ms if n.latency_ms is not None else 'n/a'}ms",
        f"download_speed={_fmt_speed(ds)}",
    ]
    return ", ".join(parts)


def _rfc822_now() -> str:
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def emit_rss(nodes: list[ProxyNode]) -> str:
    """Render RSS 2.0 feed for alive nodes -> output/feed.xml. Returns the XML."""
    pub = _rfc822_now()
    items: list[str] = []
    for n in nodes:
        title = saxutils.escape(_node_title(n))
        desc = saxutils.escape(_node_description(n))
        link = saxutils.escape(n.raw or "")
        items.append(
            "    <item>\n"
            f"      <title>{title}</title>\n"
            f"      <description>{desc}</description>\n"
            f"      <link>{link}</link>\n"
            f'      <guid isPermaLink="false">{saxutils.escape(n.dedup_key())}</guid>\n'
            f"      <pubDate>{pub}</pubDate>\n"
            "    </item>"
        )
    items_block = "\n".join(items)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        "  <channel>\n"
        "    <title>proxy-aggregator alive nodes</title>\n"
        f"    <link>{saxutils.escape(str(ROOT))}</link>\n"
        "    <description>Alive proxy nodes sorted by download speed (desc).</description>\n"
        f"    <language>en</language>\n"
        f"    <pubDate>{pub}</pubDate>\n"
        f"    <lastBuildDate>{pub}</lastBuildDate>\n"
        "    <ttl>30</ttl>\n"
        "    <generator>free-proxy aggregator</generator>\n"
        f"{items_block}\n"
        "  </channel>\n"
        "</rss>\n"
    )
    FEED_FILE.parent.mkdir(parents=True, exist_ok=True)
    FEED_FILE.write_text(xml, encoding="utf-8")
    return xml


def emit_all() -> dict:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    nodes = select_nodes()
    clash = emit_clash(nodes)
    singbox = emit_singbox(nodes)
    v2ray = emit_v2ray_b64(nodes)
    emit_rss(nodes)

    (OUTPUT_DIR / "clash.yaml").write_text(
        yaml.safe_dump(clash, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    (OUTPUT_DIR / "singbox.json").write_text(
        json.dumps(singbox, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (OUTPUT_DIR / "v2ray-base64.txt").write_text(v2ray, encoding="utf-8")

    return {
        "nodes": len(nodes),
        "clash_proxies": len(clash["proxies"]),
        "singbox_outbounds": len(singbox["outbounds"]),
        "rss_items": len(nodes),
    }


if __name__ == "__main__":
    print(json.dumps(emit_all(), ensure_ascii=False, indent=2))
