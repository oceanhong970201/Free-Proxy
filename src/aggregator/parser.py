"""Parse and serialize the proxy formats accepted by the aggregator."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import yaml

from .models import ProxyNode, validate_proxy_node


CONFIG_RE = re.compile(
    r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>]+)",
    re.IGNORECASE,
)

_TLS_DEFAULT_PROTOCOLS = {"trojan", "tuic", "hysteria2", "juicity"}


def _b64decode_loose(value: str) -> str:
    """Decode standard or URL-safe base64 with omitted padding."""
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", "ignore")
    except Exception:
        return ""


def _b64decode_strict(value: str) -> str:
    """Decode URL-safe base64 while rejecting trailing or embedded garbage."""
    value = value.strip().replace("-", "+").replace("_", "/")
    if (
        not value
        or len(value) % 4 == 1
        or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value)
    ):
        return ""
    value = value.rstrip("=")
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return ""


def _b64encode_urlsafe(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _host_port(host: str, port: int) -> str:
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{rendered_host}:{port}"


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "tls"}:
            return True
        if normalized in {"0", "false", "no", "off", "none", ""}:
            return False
    return None


def _as_non_negative_int(value: Any, *, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValueError("boolean is not an integer")
    parsed = int(value)
    if parsed < 0:
        raise ValueError("integer must be non-negative")
    return parsed


def _alpn_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, (list, tuple)):
        parts = [str(part).strip() for part in value if str(part).strip()]
        return ",".join(parts) or None
    return None


def _query_value(query: dict[str, list[str]], *names: str) -> str | None:
    lowered = {key.lower(): values for key, values in query.items()}
    for name in names:
        values = lowered.get(name.lower())
        if values:
            return values[0]
    return None


def _tls_enabled(node: ProxyNode) -> bool:
    if node.tls is not None:
        return node.tls
    if (node.security or "").lower() in {"tls", "reality"}:
        return True
    if node.pbk or node.sid:
        return True
    if node.proto.lower() in _TLS_DEFAULT_PROTOCOLS:
        return True
    return bool(node.sni)


def _uri_security(node: ProxyNode) -> str | None:
    if node.security:
        return node.security.lower()
    if node.pbk or node.sid:
        return "reality"
    if node.tls is True:
        return "tls"
    if node.tls is False:
        return "none"
    return None


def _credential(node: ProxyNode) -> str:
    proto = node.proto.lower()
    if proto in {"vless"}:
        return quote(node.uuid or "", safe="")
    if proto in {"trojan", "hysteria2", "hy2"}:
        return quote(node.password or "", safe="")
    if proto in {"tuic", "juicity"}:
        return (
            f"{quote(node.uuid or '', safe='')}:{quote(node.password or '', safe='')}"
        )
    return quote(node.uuid or node.password or "", safe="")


def _ssr_to_uri(node: ProxyNode) -> str:
    if not all((node.protocol, node.method, node.obfs, node.password is not None)):
        raise ValueError("SSR requires protocol, method, obfs and password")
    password = _b64encode_urlsafe(node.password or "")
    head = ":".join(
        (
            node.host,
            str(node.port),
            node.protocol or "origin",
            node.method or "",
            node.obfs or "plain",
            password,
        )
    )
    query: dict[str, str] = {}
    if node.obfs_param:
        query["obfsparam"] = _b64encode_urlsafe(node.obfs_param)
    if node.protocol_param:
        query["protoparam"] = _b64encode_urlsafe(node.protocol_param)
    if node.name:
        query["remarks"] = _b64encode_urlsafe(node.name)
    suffix = f"/?{urlencode(query)}" if query else "/"
    return f"ssr://{_b64encode_urlsafe(head + suffix)}"


def node_to_uri(node: ProxyNode) -> str:
    """Serialize a node without losing transport or TLS semantics."""
    validate_proxy_node(node)
    proto = (node.proto or "").lower()
    host_port = _host_port(node.host or "", node.port or 0)
    name = node.name or ""

    if proto == "vmess":
        tls_enabled = _tls_enabled(node)
        vmess_net = node.net or "tcp"
        vmess_type = "none"
        if vmess_net == "http":
            vmess_net = "tcp"
            vmess_type = "http"
        elif vmess_net == "xhttp" and node.transport_mode:
            vmess_type = node.transport_mode
        payload: dict[str, Any] = {
            "v": "2",
            "ps": name,
            "add": node.host,
            "port": str(node.port),
            "id": node.uuid or "",
            "aid": str(node.alter_id if node.alter_id is not None else 0),
            "scy": node.method or "auto",
            "net": vmess_net,
            "type": vmess_type,
            "host": node.host_header or "",
            "path": node.path or "",
            "tls": "tls" if tls_enabled else "",
            "sni": node.sni or "",
        }
        if node.fp:
            payload["fp"] = node.fp
        if node.alpn:
            payload["alpn"] = node.alpn
        if node.skip_cert_verify is not None:
            payload["allowInsecure"] = bool(node.skip_cert_verify)
        encoded = base64.b64encode(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        ).decode("ascii")
        return f"vmess://{encoded}"

    if proto == "ssr":
        return _ssr_to_uri(node)

    if proto == "ss":
        if not node.method or node.password is None:
            raise ValueError("Shadowsocks requires an explicit method and password")
        encoded_credential = _b64encode_urlsafe(f"{node.method}:{node.password}")
        fragment = f"#{quote(name, safe='')}" if name else ""
        return f"ss://{encoded_credential}@{host_port}{fragment}"

    query: dict[str, str] = {}
    if node.sni:
        query["sni"] = node.sni
    if node.net:
        query["type"] = node.net
    if node.transport_mode:
        query["mode"] = node.transport_mode
    if node.path:
        query["path"] = node.path
    if node.host_header:
        query["host"] = node.host_header
    if node.flow:
        query["flow"] = node.flow
    if node.packet_encoding:
        query["packetEncoding"] = node.packet_encoding
    if node.fp:
        query["fp"] = node.fp
    if node.utls is not None:
        query["utls"] = "1" if node.utls else "0"
    if node.alpn:
        query["alpn"] = node.alpn
    if node.pbk:
        query["pbk"] = node.pbk
    if node.sid:
        query["sid"] = node.sid
    if node.spider_x:
        query["spx"] = node.spider_x
    security = _uri_security(node)
    if security:
        query["security"] = security
    if node.skip_cert_verify is not None:
        query["allowInsecure"] = "1" if node.skip_cert_verify else "0"
    if node.obfs:
        query["obfs"] = node.obfs
    if node.obfs_param:
        query["obfs-password"] = node.obfs_param
    if node.congestion_control:
        query["congestion_control"] = node.congestion_control
    if node.udp_relay_mode:
        query["udp_relay_mode"] = node.udp_relay_mode

    query_string = urlencode(query, quote_via=quote)
    fragment = f"#{quote(name, safe='')}" if name else ""
    query_part = f"?{query_string}" if query_string else ""
    return f"{proto}://{_credential(node)}@{host_port}{query_part}{fragment}"


def extract_uris(text: str) -> list[str]:
    """Pull all supported proxy URIs from an arbitrary text blob."""
    if not text:
        return []
    result: list[str] = []
    for match in CONFIG_RE.finditer(text):
        uri = match.group(1).strip().rstrip(",;\"'")
        if uri:
            result.append(uri)
    return result


def _parse_vmess(uri: str) -> ProxyNode | None:
    raw_json = _b64decode_strict(uri[len("vmess://") :])
    if not raw_json:
        return None
    try:
        data = json.loads(raw_json)
        port = int(data.get("port") or 0)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    host = str(data.get("add") or "")
    if not host or port <= 0:
        return None
    net = str(data.get("net") or "").strip().lower() or None
    vmess_type = str(data.get("type") or data.get("headerType") or "").strip()
    if net == "raw":
        net = "tcp"
    if net == "tcp" and vmess_type.lower() == "http":
        net = "http"
    transport_mode = None
    if net == "xhttp":
        transport_mode = str(data.get("mode") or vmess_type or "").strip() or None

    tls_raw = data.get("tls")
    tls = _as_bool(tls_raw) if tls_raw is not None else None
    security = "tls" if tls is True else "none" if tls is False else None
    insecure = None
    for insecure_key in ("allowInsecure", "skip-cert-verify", "insecure"):
        if insecure_key in data:
            insecure = _as_bool(data.get(insecure_key))
            break
    try:
        alter_id = _as_non_negative_int(data.get("aid"), default=0)
    except (TypeError, ValueError):
        return None
    return ProxyNode(
        proto="vmess",
        host=host,
        port=port,
        uuid=str(data.get("id") or "") or None,
        alter_id=alter_id,
        method=str(
            data.get("scy") or data.get("method") or data.get("security") or "auto"
        )
        or None,
        sni=str(data.get("sni") or "") or None,
        net=net,
        transport_mode=transport_mode,
        path=str(data.get("path") or "") or None,
        host_header=str(data.get("host") or "") or None,
        fp=str(data.get("fp") or "") or None,
        alpn=_alpn_text(data.get("alpn")),
        pbk=str(data.get("pbk") or data.get("public-key") or "") or None,
        sid=str(data.get("sid") or data.get("short-id") or "") or None,
        security=security,
        tls=tls,
        skip_cert_verify=insecure,
        raw=uri,
        name=str(data.get("ps") or "") or None,
    )


def _parse_ss(uri: str) -> ProxyNode | None:
    candidate = uri
    try:
        parsed = urlparse(candidate)
    except Exception:
        return None

    # Legacy SIP002 encodes method:password@host:port as one base64 payload.
    if not parsed.hostname:
        body = uri[len("ss://") :].split("#", 1)[0].split("?", 1)[0]
        decoded = _b64decode_loose(body)
        if "@" not in decoded:
            return None
        candidate = f"ss://{decoded}"
        try:
            parsed = urlparse(candidate)
        except Exception:
            return None

    host = parsed.hostname or ""
    try:
        port = parsed.port or 0
    except (TypeError, ValueError):
        return None
    if not host or port <= 0:
        return None
    original_query = parse_qs(urlparse(uri).query, keep_blank_values=True)
    if _query_value(original_query, "plugin"):
        # Plugin semantics are not represented by ProxyNode emitters.
        return None

    username = unquote(parsed.username or "")
    password_part = (
        unquote(parsed.password or "") if parsed.password is not None else ""
    )
    if parsed.password is not None:
        decoded_credential = f"{username}:{password_part}"
    else:
        decoded_credential = _b64decode_loose(username)
    if ":" not in decoded_credential:
        return None
    method, password = decoded_credential.split(":", 1)
    if not method:
        return None
    fragment = urlparse(uri).fragment
    return ProxyNode(
        proto="ss",
        host=host,
        port=port,
        password=password,
        method=method,
        raw=uri,
        name=unquote(fragment) if fragment else None,
    )


def _parse_ssr(uri: str) -> ProxyNode | None:
    decoded = _b64decode_loose(uri[len("ssr://") :].split("#", 1)[0])
    if not decoded:
        return None
    head, separator, query_string = decoded.partition("/?")
    if not separator:
        head = head.rstrip("/")
        query_string = ""
    parts = head.rsplit(":", 5)
    if len(parts) != 6:
        return None
    host, port_raw, protocol, method, obfs, password_encoded = parts
    try:
        port = int(port_raw)
    except ValueError:
        return None
    if not host or port <= 0 or not method:
        return None
    query = parse_qs(query_string, keep_blank_values=True)

    def decoded_query(name: str) -> str | None:
        value = _query_value(query, name)
        return _b64decode_loose(value) if value else None

    return ProxyNode(
        proto="ssr",
        host=host,
        port=port,
        password=_b64decode_loose(password_encoded),
        method=method,
        protocol=protocol or None,
        protocol_param=decoded_query("protoparam"),
        obfs=obfs or None,
        obfs_param=decoded_query("obfsparam"),
        raw=uri,
        name=decoded_query("remarks"),
    )


def _parse_query_uri(uri: str, proto: str) -> ProxyNode | None:
    try:
        parsed = urlparse(uri)
        port = parsed.port or 0
    except (TypeError, ValueError):
        return None
    host = parsed.hostname or ""
    if not host or port <= 0:
        return None

    query = parse_qs(parsed.query, keep_blank_values=True)
    network = _query_value(query, "type", "network")
    normalized_network = {
        "websocket": "ws",
        "raw": "tcp",
        "http-upgrade": "httpupgrade",
        "http_upgrade": "httpupgrade",
    }.get((network or "").lower(), (network or "").lower()) or None
    header_type = _query_value(query, "headerType", "header-type")
    if normalized_network in {None, "tcp"} and (header_type or "").lower() == "http":
        normalized_network = "http"
    elif header_type and header_type.lower() not in {"none"}:
        return None
    transport_mode = _query_value(query, "mode")
    authority = _query_value(query, "authority")
    if authority:
        return None
    if normalized_network == "grpc":
        if transport_mode and transport_mode.lower() != "gun":
            return None
    elif normalized_network != "xhttp" and transport_mode:
        return None
    if _query_value(query, "ech") or _query_value(query, "fm"):
        return None
    username = unquote(parsed.username or "")
    uri_password = (
        unquote(parsed.password or "") if parsed.password is not None else None
    )
    joined_credential = (
        f"{username}:{uri_password}" if uri_password is not None else username
    )
    name = unquote(parsed.fragment) if parsed.fragment else None

    node = ProxyNode(proto=proto, host=host, port=port, raw=uri, name=name)
    if proto == "vless":
        node.uuid = username or None
    elif proto == "trojan":
        node.password = joined_credential or None
    elif proto in {"tuic", "juicity"}:
        node.uuid = username or _query_value(query, "uuid") or None
        node.password = uri_password or _query_value(query, "password") or None
    elif proto == "hysteria2":
        node.password = joined_credential or _query_value(query, "password") or None

    node.sni = _query_value(query, "sni", "peer", "server_name")
    node.net = normalized_network
    if normalized_network == "xhttp":
        node.transport_mode = transport_mode
    node.path = _query_value(query, "path", "serviceName", "service-name")
    node.host_header = _query_value(query, "host", "headerHost")
    node.flow = _query_value(query, "flow")
    node.packet_encoding = _query_value(
        query, "packetEncoding", "packet-encoding", "packet_encoding"
    )
    node.fp = _query_value(query, "fp", "fingerprint")
    node.alpn = _query_value(query, "alpn")
    node.pbk = _query_value(query, "pbk", "public-key", "public_key")
    node.sid = _query_value(query, "sid", "short-id", "short_id")
    node.spider_x = _query_value(query, "spx", "spider-x", "spider_x")
    security_value = _query_value(query, "security")
    if security_value is not None:
        security = security_value.strip().lower() or "none"
        node.security = security
        node.tls = security in {"tls", "reality"}
    insecure = _query_value(
        query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify"
    )
    if insecure is not None:
        node.skip_cert_verify = _as_bool(insecure)
    utls = _query_value(query, "utls")
    if utls is not None:
        node.utls = _as_bool(utls)
    elif node.fp:
        node.utls = True

    node.obfs = _query_value(query, "obfs")
    node.obfs_param = _query_value(query, "obfs-password", "obfs_password")
    node.congestion_control = _query_value(
        query, "congestion_control", "congestion-controller", "congestion_controller"
    )
    node.udp_relay_mode = _query_value(query, "udp_relay_mode", "udp-relay-mode")
    return node


def parse_uri(uri: str) -> ProxyNode | None:
    uri = uri.strip()
    lowered = uri.lower()
    node: ProxyNode | None = None
    if lowered.startswith("vmess://"):
        node = _parse_vmess(uri)
    elif lowered.startswith("ssr://"):
        node = _parse_ssr(uri)
    elif lowered.startswith("ss://"):
        node = _parse_ss(uri)
    for scheme in (
        "vless",
        "trojan",
        "tuic",
        "hysteria2",
        "hysteria",
        "hy2",
        "juicity",
    ):
        if node is None and lowered.startswith(f"{scheme}://"):
            normalized = "hysteria2" if scheme in {"hy2", "hysteria"} else scheme
            node = _parse_query_uri(uri, normalized)
            break
    if node is None:
        return None
    try:
        return validate_proxy_node(node)
    except (TypeError, ValueError):
        return None


def validate_node_raw(node: ProxyNode) -> ProxyNode:
    """Require ``raw`` to describe the same complete connection as the model."""

    validate_proxy_node(node)
    if not isinstance(node.raw, str) or not node.raw.strip():
        raise ValueError("node raw URI is empty")
    reparsed = parse_uri(node.raw)
    if reparsed is None:
        raise ValueError("node raw URI is invalid or unsupported")
    if reparsed.dedup_key() != node.dedup_key():
        raise ValueError("node raw URI does not match the structured connection")
    return node


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _case_insensitive_header(headers: dict[str, Any], name: str) -> str | None:
    for key, value in headers.items():
        if str(key).lower() == name.lower() and value is not None:
            if isinstance(value, (list, tuple)):
                value = value[0] if value else None
            if value is None:
                return None
            return str(value)
    return None


def _first_text(value: Any) -> str | None:
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    rendered = str(value)
    return rendered or None


def _transport_host(options: dict[str, Any]) -> str | None:
    return _first_text(options.get("host")) or _case_insensitive_header(
        _mapping(options.get("headers")), "Host"
    )


def parse_clash_yaml(text: str) -> list[ProxyNode]:
    """Parse the ``proxies`` segment of a Clash/Mihomo document."""
    try:
        document = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(document, dict):
        return []

    nodes: list[ProxyNode] = []
    for proxy in document.get("proxies") or []:
        if not isinstance(proxy, dict):
            continue
        proto = str(proxy.get("type") or "").lower()
        proto = "hysteria2" if proto in {"hy2", "hysteria"} else proto
        if proto not in {
            "vmess",
            "vless",
            "trojan",
            "tuic",
            "hysteria2",
            "ss",
            "ssr",
            "juicity",
        }:
            continue
        if proto == "ss" and (proxy.get("plugin") or proxy.get("plugin-opts")):
            continue
        host = str(proxy.get("server") or "")
        try:
            port = int(proxy.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not host or port <= 0:
            continue

        ws_options = _mapping(proxy.get("ws-opts"))
        grpc_options = _mapping(proxy.get("grpc-opts"))
        http_options = _mapping(proxy.get("http-opts"))
        h2_options = _mapping(proxy.get("h2-opts"))
        xhttp_options = _mapping(proxy.get("xhttp-opts"))
        upgrade_options = _mapping(
            proxy.get("http-upgrade-opts") or proxy.get("httpupgrade-opts")
        )
        reality_options = _mapping(proxy.get("reality-opts"))
        network = str(proxy.get("network") or proxy.get("net") or "") or None
        if not network and ws_options:
            network = "ws"
        if not network and grpc_options:
            network = "grpc"
        if not network and http_options:
            network = "http"
        if not network and h2_options:
            network = "h2"
        if not network and xhttp_options:
            network = "xhttp"
        if not network and upgrade_options:
            network = "httpupgrade"
        network = {
            "websocket": "ws",
            "http-upgrade": "httpupgrade",
            "http_upgrade": "httpupgrade",
        }.get((network or "").lower(), (network or "").lower()) or None

        path = None
        host_header = None
        if network == "ws":
            path = str(ws_options.get("path") or "") or None
            host_header = _case_insensitive_header(
                _mapping(ws_options.get("headers")), "Host"
            )
        elif network == "grpc":
            path = (
                str(
                    grpc_options.get("grpc-service-name")
                    or grpc_options.get("service-name")
                    or ""
                )
                or None
            )
        elif network == "http":
            path = _first_text(http_options.get("path"))
            host_header = _transport_host(http_options)
        elif network == "h2":
            path = _first_text(h2_options.get("path"))
            host_header = _transport_host(h2_options)
        elif network == "xhttp":
            path = _first_text(xhttp_options.get("path"))
            host_header = _transport_host(xhttp_options)
        elif network == "httpupgrade":
            path = _first_text(upgrade_options.get("path"))
            host_header = _transport_host(upgrade_options)

        tls = _as_bool(proxy.get("tls")) if "tls" in proxy else None
        security = None
        if reality_options:
            security = "reality"
            tls = True
        elif tls is True:
            security = "tls"
        elif tls is False:
            security = "none"

        try:
            alter_id = (
                _as_non_negative_int(
                    proxy.get("alterId", proxy.get("alter-id")), default=0
                )
                if proto == "vmess"
                else None
            )
        except (TypeError, ValueError):
            continue

        node = ProxyNode(
            proto=proto,
            host=host,
            port=port,
            alter_id=alter_id,
            method=str(proxy.get("cipher") or proxy.get("method") or "") or None,
            sni=str(
                proxy.get("servername") or proxy.get("sni") or proxy.get("peer") or ""
            )
            or None,
            net=network,
            transport_mode=(
                str(xhttp_options.get("mode") or "") or None
                if network == "xhttp"
                else None
            ),
            path=path,
            host_header=host_header,
            flow=str(proxy.get("flow") or "") or None,
            packet_encoding=str(proxy.get("packet-encoding") or "") or None,
            fp=str(proxy.get("client-fingerprint") or "") or None,
            alpn=_alpn_text(proxy.get("alpn")),
            pbk=str(reality_options.get("public-key") or "") or None,
            sid=str(reality_options.get("short-id") or "") or None,
            spider_x=str(reality_options.get("spider-x") or "") or None,
            security=security,
            tls=tls,
            skip_cert_verify=(
                _as_bool(proxy.get("skip-cert-verify"))
                if "skip-cert-verify" in proxy
                else None
            ),
            protocol=str(proxy.get("protocol") or "") or None,
            protocol_param=str(proxy.get("protocol-param") or "") or None,
            obfs=str(proxy.get("obfs") or "") or None,
            obfs_param=str(proxy.get("obfs-param") or proxy.get("obfs-password") or "")
            or None,
            congestion_control=str(
                proxy.get("congestion-controller")
                or proxy.get("congestion_control")
                or ""
            )
            or None,
            udp_relay_mode=str(proxy.get("udp-relay-mode") or "") or None,
            name=str(proxy.get("name") or "") or None,
            raw="",
        )

        if proto in {"vmess", "vless"}:
            node.uuid = str(proxy.get("uuid") or "") or None
        elif proto in {"trojan", "hysteria2", "ss", "ssr"}:
            node.password = str(proxy.get("password") or "") or None
        elif proto in {"tuic", "juicity"}:
            node.uuid = str(proxy.get("uuid") or "") or None
            node.password = str(proxy.get("password") or "") or None

        try:
            validate_proxy_node(node)
            node.raw = node_to_uri(node)
        except (TypeError, ValueError):
            continue
        nodes.append(node)
    return nodes


def parse_singbox_json(text: str) -> list[ProxyNode]:
    """Parse supported proxy outbounds from a sing-box document."""
    try:
        document = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return []
    outbounds = document.get("outbounds") if isinstance(document, dict) else document
    if not isinstance(outbounds, list):
        return []

    type_map = {
        "vmess": "vmess",
        "vless": "vless",
        "trojan": "trojan",
        "tuic": "tuic",
        "hysteria2": "hysteria2",
        "hysteria": "hysteria2",
        "shadowsocks": "ss",
    }
    nodes: list[ProxyNode] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        proto = type_map.get(str(outbound.get("type") or "").lower())
        if not proto:
            continue
        if proto == "ss" and (outbound.get("plugin") or outbound.get("plugin_opts")):
            continue
        host = str(outbound.get("server") or "")
        try:
            port = int(outbound.get("server_port") or outbound.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not host or port <= 0:
            continue

        transport = _mapping(outbound.get("transport"))
        network = str(transport.get("type") or "").lower() or None
        network = {
            "websocket": "ws",
            "http-upgrade": "httpupgrade",
            "http_upgrade": "httpupgrade",
        }.get(network or "", network)
        path = None
        host_header = None
        if network == "ws":
            path = str(transport.get("path") or "") or None
            host_header = _case_insensitive_header(
                _mapping(transport.get("headers")), "Host"
            )
        elif network == "grpc":
            path = str(transport.get("service_name") or "") or None
        elif network in {"http", "httpupgrade", "xhttp"}:
            path = str(transport.get("path") or "") or None
            host_header = _first_text(
                transport.get("host")
            ) or _case_insensitive_header(_mapping(transport.get("headers")), "Host")

        tls_options = _mapping(outbound.get("tls"))
        tls = _as_bool(tls_options.get("enabled")) if "enabled" in tls_options else None
        reality_options = _mapping(tls_options.get("reality"))
        reality_enabled = (
            _as_bool(reality_options.get("enabled"))
            if "enabled" in reality_options
            else bool(reality_options)
        )
        security = (
            "reality"
            if reality_enabled
            else "tls"
            if tls
            else "none"
            if tls is False
            else None
        )
        utls_options = _mapping(tls_options.get("utls"))
        obfs_options = _mapping(outbound.get("obfs"))

        try:
            alter_id = (
                _as_non_negative_int(outbound.get("alter_id"), default=0)
                if proto == "vmess"
                else None
            )
        except (TypeError, ValueError):
            continue

        node = ProxyNode(
            proto=proto,
            host=host,
            port=port,
            alter_id=alter_id,
            method=str(
                outbound.get("method")
                or (outbound.get("security") if proto == "vmess" else "")
                or ""
            )
            or None,
            sni=str(tls_options.get("server_name") or "") or None,
            net=network,
            transport_mode=(
                str(transport.get("mode") or "") or None if network == "xhttp" else None
            ),
            path=path,
            host_header=host_header,
            flow=str(outbound.get("flow") or "") or None,
            packet_encoding=str(outbound.get("packet_encoding") or "") or None,
            fp=str(utls_options.get("fingerprint") or "") or None,
            alpn=_alpn_text(tls_options.get("alpn")),
            pbk=str(reality_options.get("public_key") or "") or None,
            sid=str(reality_options.get("short_id") or "") or None,
            security=security,
            tls=tls,
            utls=(
                _as_bool(utls_options.get("enabled"))
                if "enabled" in utls_options
                else (True if utls_options else None)
            ),
            skip_cert_verify=(
                _as_bool(tls_options.get("insecure"))
                if "insecure" in tls_options
                else None
            ),
            obfs=str(obfs_options.get("type") or "") or None,
            obfs_param=str(obfs_options.get("password") or "") or None,
            congestion_control=str(outbound.get("congestion_control") or "") or None,
            udp_relay_mode=str(outbound.get("udp_relay_mode") or "") or None,
            name=str(outbound.get("tag") or "") or None,
            raw="",
        )

        if proto in {"vmess", "vless"}:
            node.uuid = str(outbound.get("uuid") or "") or None
        elif proto in {"trojan", "hysteria2", "ss"}:
            node.password = str(outbound.get("password") or "") or None
        elif proto == "tuic":
            node.uuid = str(outbound.get("uuid") or "") or None
            node.password = str(outbound.get("password") or "") or None
        try:
            validate_proxy_node(node)
            node.raw = node_to_uri(node)
        except (TypeError, ValueError):
            continue
        nodes.append(node)
    return nodes


def parse_v2ray_base64(text: str) -> list[ProxyNode]:
    """Parse a whole-blob or line-oriented v2ray base64 subscription."""
    if not text:
        return []
    decoded = _b64decode_loose(text.strip())
    candidates = [decoded] if decoded else []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        line_decoded = _b64decode_loose(line)
        if line_decoded and "://" in line_decoded:
            candidates.append(line_decoded)
        elif "://" in line:
            candidates.append(line)

    nodes: list[ProxyNode] = []
    seen: set[str] = set()
    for candidate in candidates:
        for uri in extract_uris(candidate):
            if uri in seen:
                continue
            seen.add(uri)
            node = parse_uri(uri)
            if node:
                nodes.append(node)
    return nodes


def parse_raw(source_format: str, text: str) -> list[ProxyNode]:
    """Dispatch a source body to the corresponding parser."""
    source_format = (source_format or "").lower()
    if source_format in {"clash", "clash.yaml", "yaml"}:
        nodes = parse_clash_yaml(text)
        known_raw = {node.raw for node in nodes}
        for uri in extract_uris(text):
            node = parse_uri(uri)
            if node and node.raw not in known_raw:
                nodes.append(node)
                known_raw.add(node.raw)
        return nodes
    if source_format in {"singbox", "sing-box", "json"}:
        return parse_singbox_json(text)
    if source_format in {"v2ray", "v2ray-base64", "base64"}:
        return parse_v2ray_base64(text)

    nodes: list[ProxyNode] = []
    seen: set[str] = set()
    for uri in extract_uris(text):
        if uri in seen:
            continue
        seen.add(uri)
        node = parse_uri(uri)
        if node:
            nodes.append(node)
    return nodes
