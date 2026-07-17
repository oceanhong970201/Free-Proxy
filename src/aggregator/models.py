"""Pydantic models shared by the aggregator pipeline."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


SUPPORTED_PROTOCOLS = {
    "vmess",
    "vless",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "tuic",
    "juicity",
}
SUPPORTED_TRANSPORTS = {
    "tcp",
    "ws",
    "grpc",
    "http",
    "h2",
    "xhttp",
    "httpupgrade",
}
TLS_DEFAULT_PROTOCOLS = {"trojan", "tuic", "hysteria2", "juicity"}


class ProxyNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Connection fields. ``raw`` is retained for subscription output, but is
    # deliberately not part of the semantic connection key.
    proto: str  # vmess|vless|trojan|ss|ssr|hysteria2|tuic|juicity
    host: str
    port: int
    uuid: str | None = None
    alter_id: int | None = None  # VMess alterId; 0 is the modern default
    password: str | None = None
    method: str | None = None  # SS/SSR cipher or VMess security
    sni: str | None = None
    net: str | None = None  # ws|tcp|grpc|http
    transport_mode: str | None = None  # XHTTP mode (auto/packet-up/stream-up)
    path: str | None = None  # WS path or gRPC service name
    host_header: str | None = None
    flow: str | None = None
    packet_encoding: str | None = None  # VLESS packet encoding (xudp/packetaddr)
    fp: str | None = None
    alpn: str | None = None  # comma-separated for SQLite compatibility
    pbk: str | None = None
    sid: str | None = None
    spider_x: str | None = None  # Reality spiderX path
    security: str | None = None  # none|tls|reality (URI security mode)
    tls: bool | None = None  # explicit TLS state; None means protocol default
    utls: bool | None = None  # explicit sing-box uTLS state
    skip_cert_verify: bool | None = None
    # ShadowsocksR / Hysteria2 transport settings.
    protocol: str | None = None
    protocol_param: str | None = None
    obfs: str | None = None
    obfs_param: str | None = None
    # TUIC / Juicity settings.
    congestion_control: str | None = None
    udp_relay_mode: str | None = None
    raw: str
    name: str | None = None
    # Runtime-only liveness and provenance.
    source: str | None = None
    alive: bool | None = None
    latency_ms: int | None = None
    download_speed: float | None = None
    content_hash: str | None = None

    def dedup_key(self) -> str:
        """Hash every connection-relevant setting.

        Display names, provenance, liveness and the original serialization do
        not affect whether two nodes establish the same connection. Values
        that are inherently case-insensitive are normalized; credentials and
        URI paths remain byte-for-byte significant.
        """
        import hashlib
        import json

        excluded = {
            "raw",
            "name",
            "source",
            "alive",
            "latency_ms",
            "download_speed",
            "content_hash",
        }
        values = self.model_dump(exclude=excluded, exclude_none=False)
        values["proto"] = (self.proto or "").lower()
        values["host"] = (self.host or "").lower()
        for key in ("sni", "net", "security"):
            value = values.get(key)
            if isinstance(value, str):
                values[key] = value.lower()
        payload = json.dumps(
            values, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


def validate_proxy_node(node: ProxyNode) -> ProxyNode:
    """Validate and normalize one complete connection at a parser boundary.

    ``ProxyNode`` is also used while a structured Clash/sing-box entry is being
    assembled, so protocol-specific checks intentionally live here rather than
    in a Pydantic model validator.  Every parser and emitter calls this helper
    once the connection is complete.
    """

    proto = (node.proto or "").strip().lower()
    if proto not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"unsupported proxy protocol: {proto or '<empty>'}")
    node.proto = proto

    for field_name in (
        "method",
        "sni",
        "net",
        "transport_mode",
        "path",
        "host_header",
        "flow",
        "packet_encoding",
        "fp",
        "alpn",
        "pbk",
        "sid",
        "spider_x",
        "protocol",
        "protocol_param",
        "obfs",
        "obfs_param",
        "congestion_control",
        "udp_relay_mode",
    ):
        value = getattr(node, field_name)
        if isinstance(value, str) and not value:
            setattr(node, field_name, None)

    if proto == "vmess" and not node.method:
        node.method = "auto"
    if node.fp and node.utls is None:
        node.utls = True

    if isinstance(node.security, str):
        normalized_security = node.security.strip().lower()
        node.security = normalized_security or None
    if node.security not in {None, "none", "tls", "reality"}:
        raise ValueError(f"unsupported security mode: {node.security}")
    if node.pbk or node.sid:
        if node.security == "none":
            raise ValueError("Reality parameters conflict with security=none")
        node.security = "reality"
    if node.security is None:
        if node.tls is True:
            node.security = "tls"
        elif node.tls is False:
            node.security = "none"
        elif proto in TLS_DEFAULT_PROTOCOLS:
            node.security = "tls"
            node.tls = True
        elif proto in {"vmess", "vless"}:
            if node.sni or node.fp or node.alpn or node.skip_cert_verify:
                node.security = "tls"
                node.tls = True
            else:
                node.security = "none"
                node.tls = False
    if node.security in {"tls", "reality"}:
        if node.tls is False:
            raise ValueError(f"security={node.security} conflicts with tls=false")
        node.tls = True
    elif node.security == "none":
        if node.tls is True:
            raise ValueError("security=none conflicts with tls=true")
        node.tls = False
    if node.security == "reality" and not (node.pbk or "").strip():
        raise ValueError("Reality requires a public key")
    if node.spider_x and node.security != "reality":
        raise ValueError("spider_x requires Reality security")
    if proto in TLS_DEFAULT_PROTOCOLS and node.tls is not True:
        raise ValueError(f"{proto} requires TLS")
    if node.tls is False:
        # These knobs do not participate in a plaintext connection. Removing
        # them prevents equivalent non-TLS URIs from producing distinct keys
        # or being reinterpreted as TLS during a later round trip.
        node.sni = None
        node.fp = None
        node.alpn = None
        node.utls = None
        node.skip_cert_verify = None

    if not isinstance(node.host, str) or not node.host.strip():
        raise ValueError(f"{proto} requires a non-empty host")
    if isinstance(node.port, bool) or not 1 <= int(node.port) <= 65535:
        raise ValueError(f"{proto} port must be between 1 and 65535")

    if proto in {"vmess", "vless", "trojan"} and not node.net:
        node.net = "tcp"
    if node.net:
        aliases = {
            "websocket": "ws",
            "raw": "tcp",
            "http-upgrade": "httpupgrade",
            "http_upgrade": "httpupgrade",
        }
        net = aliases.get(node.net.strip().lower(), node.net.strip().lower())
        if net not in SUPPORTED_TRANSPORTS:
            raise ValueError(f"unsupported {proto} transport: {net}")
        if proto not in {"vmess", "vless", "trojan"}:
            raise ValueError(f"{proto} does not support V2Ray transport {net}")
        node.net = net
    if node.net == "tcp":
        node.path = None
        node.host_header = None
    elif node.net == "grpc" and node.host_header:
        raise ValueError("gRPC authority/host override is not supported")
    if node.net == "xhttp":
        mode = (node.transport_mode or "").strip().lower()
        node.transport_mode = "auto" if mode in {"", "none"} else mode
        if node.transport_mode not in {
            "auto",
            "packet-up",
            "stream-up",
            "stream-one",
        }:
            raise ValueError(f"unsupported xhttp mode: {node.transport_mode}")
    elif node.transport_mode:
        raise ValueError("transport_mode is only valid for xhttp")

    if proto in {"vmess", "vless"} and not (node.uuid or "").strip():
        raise ValueError(f"{proto} requires uuid")
    if proto in {"vmess", "vless", "tuic", "juicity"} and node.uuid:
        from uuid import UUID

        try:
            node.uuid = str(UUID(node.uuid.strip()))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError(f"{proto} uuid is invalid") from exc
    if node.packet_encoding:
        node.packet_encoding = node.packet_encoding.strip().lower()
        if proto != "vless" or node.packet_encoding not in {"xudp", "packetaddr"}:
            raise ValueError(
                f"unsupported {proto} packet encoding: {node.packet_encoding}"
            )
    if proto == "vmess":
        if node.alter_id is None:
            node.alter_id = 0
        if isinstance(node.alter_id, bool) or node.alter_id < 0:
            raise ValueError("vmess alter_id must be a non-negative integer")
    elif node.alter_id is not None:
        raise ValueError(f"alter_id is only valid for vmess, not {proto}")

    if proto in {"trojan", "hysteria2"} and not (node.password or ""):
        raise ValueError(f"{proto} requires password")
    if proto in {"tuic", "juicity"} and (
        not (node.uuid or "").strip() or not (node.password or "")
    ):
        raise ValueError(f"{proto} requires uuid and password")
    if proto == "ss" and (not (node.method or "").strip() or not node.password):
        raise ValueError("Shadowsocks requires method and password")
    if proto == "ssr" and not all(
        (
            (node.method or "").strip(),
            node.password,
            (node.protocol or "").strip(),
            (node.obfs or "").strip(),
        )
    ):
        raise ValueError("ShadowsocksR requires method, password, protocol and obfs")
    return node


class Source(BaseModel):
    id: str
    url: str
    mirrors: list[str] = Field(default_factory=list)
    format: str
    enabled: bool = True
    tier: int = 3
    last_fetch: int | None = None
    last_count: int | None = None
    status: str = "unknown"
