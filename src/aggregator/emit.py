"""Render verified proxy nodes into client subscription formats."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from xml.sax import saxutils

import yaml

from .models import ProxyNode, validate_proxy_node
from .parser import node_to_uri, validate_node_raw


ROOT = Path(__file__).resolve().parents[2]
LIVE_FILE = ROOT / "state" / "live.jsonl"
OUTPUT_DIR = ROOT / "output"
FEED_FILE = OUTPUT_DIR / "feed.xml"
PIPELINE_STATUS_SCHEMA_VERSION = 1

_TLS_DEFAULT_PROTOCOLS = {"trojan", "tuic", "hysteria2", "juicity"}
_SS_METHOD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class UnsupportedOutbound(ValueError):
    """The node cannot be represented by a target client schema."""


class InvalidLiveSnapshot(ValueError):
    """The live snapshot is malformed and must not replace published output."""


class InvalidPipelineStatus(ValueError):
    """The public pipeline status does not satisfy its fixed, sanitized schema."""


def _utc_rfc3339() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _count(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise InvalidPipelineStatus(f"{name} must be a non-negative integer")
    return value


def validate_pipeline_status(document: object) -> dict:
    """Validate and return a status document without accepting extension fields.

    Keeping the public schema closed prevents a future caller from accidentally
    serializing provider errors, proxy URIs, credentials, or CI tokens into the
    Pages artifact.
    """

    if not isinstance(document, dict):
        raise InvalidPipelineStatus("pipeline status must be an object")
    if set(document) != {
        "schema_version",
        "generated_at",
        "pipeline_status",
        "verify",
        "artifacts",
    }:
        raise InvalidPipelineStatus("pipeline status has unknown or missing fields")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != PIPELINE_STATUS_SCHEMA_VERSION
    ):
        raise InvalidPipelineStatus("unsupported pipeline status schema_version")
    pipeline_status = document["pipeline_status"]
    if not isinstance(pipeline_status, str) or pipeline_status not in {
        "healthy",
        "unknown",
    }:
        raise InvalidPipelineStatus("pipeline_status must be healthy or unknown")

    generated_at = document["generated_at"]
    if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
        raise InvalidPipelineStatus("generated_at must be an RFC3339 UTC timestamp")
    try:
        parsed_at = datetime.fromisoformat(generated_at[:-1] + "+00:00")
    except ValueError as exc:
        raise InvalidPipelineStatus(
            "generated_at must be an RFC3339 UTC timestamp"
        ) from exc
    if parsed_at.tzinfo is None or parsed_at.utcoffset() != timezone.utc.utcoffset(
        None
    ):
        raise InvalidPipelineStatus("generated_at must be UTC")

    verify = document["verify"]
    if not isinstance(verify, dict) or set(verify) != {
        "total",
        "verified",
        "alive",
        "dead",
        "unverified",
        "tier1_alive",
        "tier2_passed",
        "completed",
    }:
        raise InvalidPipelineStatus("verify has unknown or missing fields")
    counts = {
        key: _count(verify[key], f"verify.{key}")
        for key in (
            "total",
            "verified",
            "alive",
            "dead",
            "unverified",
            "tier1_alive",
            "tier2_passed",
        )
    }
    if type(verify["completed"]) is not bool:
        raise InvalidPipelineStatus("verify.completed must be a boolean")
    if counts["verified"] + counts["unverified"] != counts["total"]:
        raise InvalidPipelineStatus("verify total equation does not hold")
    if counts["alive"] + counts["dead"] != counts["verified"]:
        raise InvalidPipelineStatus("verify verified equation does not hold")
    if counts["tier1_alive"] > counts["alive"]:
        raise InvalidPipelineStatus("tier1_alive cannot exceed alive")
    if counts["tier2_passed"] > counts["tier1_alive"]:
        raise InvalidPipelineStatus("tier2_passed cannot exceed tier1_alive")

    artifacts = document["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "node_count",
        "clash_proxies",
        "singbox_outbounds",
        "rss_items",
    }:
        raise InvalidPipelineStatus("artifacts has unknown or missing fields")
    artifact_counts = {
        key: _count(artifacts[key], f"artifacts.{key}") for key in artifacts
    }
    if artifact_counts["clash_proxies"] != artifact_counts["node_count"]:
        raise InvalidPipelineStatus("clash_proxies must match artifact node_count")
    if artifact_counts["rss_items"] != artifact_counts["node_count"]:
        raise InvalidPipelineStatus("rss_items must match artifact node_count")
    if artifact_counts["singbox_outbounds"] > artifact_counts["node_count"]:
        raise InvalidPipelineStatus("singbox_outbounds cannot exceed node_count")
    if pipeline_status == "healthy":
        if verify["completed"] is not True:
            raise InvalidPipelineStatus("healthy verify.completed must be true")
        if counts["total"] == 0:
            raise InvalidPipelineStatus("healthy verify.total must be positive")
        if counts["unverified"] != 0 or counts["verified"] != counts["total"]:
            raise InvalidPipelineStatus("a healthy snapshot must be fully verified")
        if counts["tier1_alive"] != counts["alive"]:
            raise InvalidPipelineStatus("healthy tier1_alive must match alive")
        if artifact_counts["node_count"] != counts["alive"]:
            raise InvalidPipelineStatus("healthy artifact node_count must match alive")
    elif verify["completed"] is not False:
        raise InvalidPipelineStatus("unknown verify.completed must be false")
    return document


def _pipeline_status_document(
    all_nodes: list[ProxyNode],
    *,
    verify_summary: dict,
    clash_proxies: int,
    singbox_outbounds: int,
    rss_items: int,
    generated_at: str | None = None,
) -> dict:
    """Build the only public status shape from count-only local inputs."""

    alive = sum(node.alive is True for node in all_nodes)
    dead = sum(node.alive is False for node in all_nodes)
    unverified = sum(node.alive is None for node in all_nodes)
    total = len(all_nodes)
    verified = alive + dead

    if verify_summary.get("success") is not True:
        raise InvalidPipelineStatus("the preceding verify run was not successful")
    if verify_summary.get("completed") is not True:
        raise InvalidPipelineStatus("the preceding verify run was not completed")
    tier1_alive = _count(verify_summary.get("tier1_alive"), "tier1_alive")
    tier2_passed = _count(verify_summary.get("tier2_passed"), "tier2_passed")
    if _count(verify_summary.get("total_alive"), "total_alive") != alive:
        raise InvalidPipelineStatus("verify alive count does not match live snapshot")
    if _count(verify_summary.get("unverified"), "unverified") != unverified:
        raise InvalidPipelineStatus(
            "verify unverified count does not match live snapshot"
        )

    document = {
        "schema_version": PIPELINE_STATUS_SCHEMA_VERSION,
        "generated_at": generated_at or _utc_rfc3339(),
        "pipeline_status": "healthy",
        "verify": {
            "total": total,
            "verified": verified,
            "alive": alive,
            "dead": dead,
            "unverified": unverified,
            "tier1_alive": tier1_alive,
            "tier2_passed": tier2_passed,
            "completed": True,
        },
        "artifacts": {
            "node_count": alive,
            "clash_proxies": clash_proxies,
            "singbox_outbounds": singbox_outbounds,
            "rss_items": rss_items,
        },
    }
    return validate_pipeline_status(document)


def _unknown_pipeline_status_document(
    all_nodes: list[ProxyNode],
    *,
    node_count: int,
    clash_proxies: int,
    singbox_outbounds: int,
    rss_items: int,
    generated_at: str | None = None,
) -> dict:
    """Build a conservative status when no completed verify proof is supplied."""

    alive = sum(node.alive is True for node in all_nodes)
    dead = sum(node.alive is False for node in all_nodes)
    unverified = sum(node.alive is None for node in all_nodes)
    document = {
        "schema_version": PIPELINE_STATUS_SCHEMA_VERSION,
        "generated_at": generated_at or _utc_rfc3339(),
        "pipeline_status": "unknown",
        "verify": {
            "total": len(all_nodes),
            "verified": alive + dead,
            "alive": alive,
            "dead": dead,
            "unverified": unverified,
            # Without the immediately preceding verifier proof, do not infer
            # tier completion from mutable node fields.
            "tier1_alive": 0,
            "tier2_passed": 0,
            "completed": False,
        },
        "artifacts": {
            "node_count": node_count,
            "clash_proxies": clash_proxies,
            "singbox_outbounds": singbox_outbounds,
            "rss_items": rss_items,
        },
    }
    return validate_pipeline_status(document)


def validate_pipeline_status_artifact(
    output_dir: Path | None = None,
    *,
    require_healthy: bool = False,
) -> dict:
    """Validate the public status and its count-only artifact contract."""

    root = output_dir or OUTPUT_DIR
    status_path = root / "pipeline-status.json"
    try:
        document = validate_pipeline_status(
            json.loads(status_path.read_text(encoding="utf-8"))
        )
        clash = yaml.safe_load((root / "clash.yaml").read_text(encoding="utf-8"))
        singbox = json.loads((root / "singbox.json").read_text(encoding="utf-8"))
        decoded = base64.b64decode(
            (root / "v2ray-base64.txt").read_text(encoding="utf-8").strip(),
            validate=True,
        ).decode("utf-8")
        rss_root = ET.parse(root / "feed.xml").getroot()
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        ET.ParseError,
        yaml.YAMLError,
    ) as exc:
        raise InvalidPipelineStatus("published output is missing or malformed") from exc

    if not isinstance(clash, dict) or not isinstance(clash.get("proxies"), list):
        raise InvalidPipelineStatus("clash artifact has an invalid proxy list")
    if not isinstance(singbox, dict) or not isinstance(singbox.get("outbounds"), list):
        raise InvalidPipelineStatus("sing-box artifact has an invalid outbound list")
    actual = {
        "node_count": len([line for line in decoded.splitlines() if line.strip()]),
        "clash_proxies": len(clash["proxies"]),
        "singbox_outbounds": len(singbox["outbounds"]),
        "rss_items": len(rss_root.findall("./channel/item")),
    }
    if actual != document["artifacts"]:
        raise InvalidPipelineStatus("pipeline status artifact counts do not match")
    if require_healthy and document["pipeline_status"] != "healthy":
        raise InvalidPipelineStatus("pipeline status is not healthy")
    return {
        "schema_version": document["schema_version"],
        "pipeline_status": document["pipeline_status"],
        **actual,
        "success": True,
    }


def load_live_nodes() -> list[ProxyNode]:
    if not LIVE_FILE.exists():
        return []
    nodes: list[ProxyNode] = []
    for line_number, line in enumerate(
        LIVE_FILE.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            document = json.loads(line)
            if not isinstance(document, dict):
                raise TypeError("record is not an object")
            node = ProxyNode(**document)
            validate_node_raw(node)
            nodes.append(node)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise InvalidLiveSnapshot(
                f"invalid live.jsonl record at line {line_number}: {exc}"
            ) from exc
    return nodes


def _download_speed(node: ProxyNode) -> float | None:
    return node.download_speed


def filter_alive(
    nodes: list[ProxyNode], *, include_unverified: bool = False
) -> list[ProxyNode]:
    """Select publishable nodes.

    Normal publication requires a positive verification result. Verification
    tools may opt into unverified nodes explicitly, while dead nodes remain
    excluded in both modes.
    """
    if include_unverified:
        return [node for node in nodes if node.alive is not False]
    return [node for node in nodes if node.alive is True]


def sort_nodes(nodes: list[ProxyNode]) -> list[ProxyNode]:
    has_speed = any(_download_speed(node) is not None for node in nodes)

    def latency_key(node: ProxyNode) -> tuple[int, str, int]:
        latency = node.latency_ms if node.latency_ms is not None else 10**9
        return latency, node.host or "", node.port or 0

    def speed_key(node: ProxyNode) -> tuple[float, int, str, int]:
        speed = _download_speed(node)
        latency = node.latency_ms if node.latency_ms is not None else 10**9
        return -(speed if speed is not None else -1.0), latency, node.host, node.port

    return sorted(nodes, key=speed_key if has_speed else latency_key)


def select_nodes(*, include_unverified: bool = False) -> list[ProxyNode]:
    return sort_nodes(
        filter_alive(load_live_nodes(), include_unverified=include_unverified)
    )


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


def _alpn_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _base_name(node: ProxyNode) -> str:
    name = re.sub(r"\s+", " ", node.name or "").strip()
    return name or f"{node.proto}-{node.host}:{node.port}"


def _validate_credentials(node: ProxyNode) -> None:
    try:
        validate_proxy_node(node)
    except (TypeError, ValueError) as exc:
        raise UnsupportedOutbound(str(exc)) from exc
    proto = node.proto.lower()
    if proto == "ss":
        if (
            not node.method
            or not _SS_METHOD_RE.fullmatch(node.method)
            or not node.password
        ):
            raise UnsupportedOutbound(
                "Shadowsocks requires an explicit valid method and password"
            )


def _add_clash_transport(output: dict, node: ProxyNode) -> None:
    net = (node.net or "").lower()
    if node.proto not in {"vmess", "vless", "trojan"}:
        return
    output["network"] = net or "tcp"
    if net in {"ws", "websocket"}:
        options: dict = {}
        if node.path:
            options["path"] = node.path
        if node.host_header:
            options["headers"] = {"Host": node.host_header}
        output["ws-opts"] = options
    elif net == "grpc":
        options = {}
        if node.path:
            options["grpc-service-name"] = node.path
        output["grpc-opts"] = options
    elif net == "http":
        options = {"method": "GET"}
        if node.path:
            options["path"] = [node.path]
        if node.host_header:
            options["headers"] = {"Host": [node.host_header]}
        output["http-opts"] = options
    elif net == "h2":
        options = {}
        if node.path:
            options["path"] = node.path
        if node.host_header:
            options["host"] = [node.host_header]
        output["h2-opts"] = options
    elif net == "xhttp":
        options = {}
        if node.path:
            options["path"] = node.path
        if node.host_header:
            options["host"] = node.host_header
        if node.transport_mode:
            options["mode"] = node.transport_mode
        output["xhttp-opts"] = options
    elif net == "httpupgrade":
        options = {}
        if node.path:
            options["path"] = node.path
        if node.host_header:
            options["host"] = node.host_header
        output["http-upgrade-opts"] = options
    elif net not in {"", "tcp"}:
        raise UnsupportedOutbound(f"unsupported Clash transport: {net}")


def to_clash_dict(node: ProxyNode) -> dict:
    """Convert one node to a Mihomo/Clash proxy mapping."""
    proto = node.proto.lower()
    if proto not in {
        "vmess",
        "vless",
        "trojan",
        "ss",
        "ssr",
        "hysteria2",
        "tuic",
    }:
        raise UnsupportedOutbound(f"unsupported Clash protocol: {proto}")
    _validate_credentials(node)

    output: dict = {
        "name": _base_name(node),
        "type": proto,
        "server": node.host,
        "port": node.port,
        "udp": True,
    }
    if proto == "vmess":
        output.update(
            {
                "uuid": node.uuid,
                "alterId": node.alter_id if node.alter_id is not None else 0,
                "cipher": node.method or "auto",
            }
        )
    elif proto == "vless":
        output["uuid"] = node.uuid
        if node.flow:
            output["flow"] = node.flow
        if node.packet_encoding:
            output["packet-encoding"] = node.packet_encoding
    elif proto == "trojan":
        output["password"] = node.password
    elif proto == "ss":
        output.update({"cipher": node.method, "password": node.password})
    elif proto == "ssr":
        output.update(
            {
                "cipher": node.method,
                "password": node.password,
                "protocol": node.protocol,
                "obfs": node.obfs,
            }
        )
        if node.protocol_param:
            output["protocol-param"] = node.protocol_param
        if node.obfs_param:
            output["obfs-param"] = node.obfs_param
    elif proto == "hysteria2":
        output["password"] = node.password
        if node.obfs:
            output["obfs"] = node.obfs
        if node.obfs_param:
            output["obfs-password"] = node.obfs_param
    elif proto == "tuic":
        output.update({"uuid": node.uuid, "password": node.password})
        if node.congestion_control:
            output["congestion-controller"] = node.congestion_control
        if node.udp_relay_mode:
            output["udp-relay-mode"] = node.udp_relay_mode

    _add_clash_transport(output, node)

    tls_enabled = _tls_enabled(node)
    if proto in {"vmess", "vless"} and (
        node.tls is not None or node.security is not None or tls_enabled
    ):
        output["tls"] = tls_enabled
    if node.sni:
        if proto in {"vmess", "vless"}:
            output["servername"] = node.sni
        elif proto not in {"ss", "ssr"}:
            output["sni"] = node.sni
    if node.skip_cert_verify is not None and proto not in {"ss", "ssr"}:
        output["skip-cert-verify"] = bool(node.skip_cert_verify)
    if node.fp and proto not in {"ss", "ssr", "hysteria2"}:
        output["client-fingerprint"] = node.fp
    alpn = _alpn_list(node.alpn)
    if alpn and proto not in {"ss", "ssr"}:
        output["alpn"] = alpn
    if node.pbk or node.sid or (node.security or "").lower() == "reality":
        reality: dict = {}
        if node.pbk:
            reality["public-key"] = node.pbk
        if node.sid:
            reality["short-id"] = node.sid
        if node.spider_x:
            reality["spider-x"] = node.spider_x
        output["reality-opts"] = reality
        if proto in {"vmess", "vless"}:
            output["tls"] = True
    return output


def _add_singbox_transport(output: dict, node: ProxyNode) -> None:
    if node.proto not in {"vmess", "vless", "trojan"}:
        return
    net = (node.net or "").lower()
    if net in {"", "tcp"}:
        return
    if net in {"ws", "websocket"}:
        transport: dict = {"type": "ws"}
        if node.path:
            transport["path"] = node.path
        if node.host_header:
            transport["headers"] = {"Host": node.host_header}
        output["transport"] = transport
    elif net == "grpc":
        transport = {"type": "grpc"}
        if node.path:
            transport["service_name"] = node.path
        output["transport"] = transport
    elif net in {"http", "h2"}:
        transport = {"type": "http"}
        if node.path:
            transport["path"] = node.path
        if node.host_header:
            transport["host"] = [node.host_header]
        output["transport"] = transport
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if node.path:
            transport["path"] = node.path
        if node.host_header:
            transport["host"] = node.host_header
        output["transport"] = transport
    elif net == "xhttp":
        raise UnsupportedOutbound("sing-box does not support xhttp transport")
    else:
        raise UnsupportedOutbound(f"unsupported sing-box transport: {net}")


def _singbox_tls(node: ProxyNode) -> dict | None:
    proto = node.proto.lower()
    relevant = (
        proto in _TLS_DEFAULT_PROTOCOLS
        or node.tls is not None
        or node.security is not None
        or bool(node.sni or node.fp or node.pbk or node.sid or node.alpn)
    )
    if not relevant:
        return None

    tls: dict = {"enabled": _tls_enabled(node)}
    if node.sni:
        tls["server_name"] = node.sni
    if node.skip_cert_verify is not None:
        tls["insecure"] = bool(node.skip_cert_verify)
    alpn = _alpn_list(node.alpn)
    if alpn:
        tls["alpn"] = alpn
    if node.fp or node.utls is not None:
        utls: dict = {
            "enabled": node.utls if node.utls is not None else True,
        }
        if node.fp:
            utls["fingerprint"] = node.fp
        tls["utls"] = utls
    if node.pbk or node.sid or (node.security or "").lower() == "reality":
        reality: dict = {"enabled": True}
        if node.pbk:
            reality["public_key"] = node.pbk
        if node.sid:
            reality["short_id"] = node.sid
        tls["reality"] = reality
        tls["enabled"] = True
    return tls


def to_singbox_outbound(node: ProxyNode) -> dict:
    """Convert one node to a current sing-box outbound mapping."""
    proto = node.proto.lower()
    # sing-box has no native ShadowsocksR or Juicity outbound.
    if proto in {"ssr", "juicity"}:
        raise UnsupportedOutbound(f"sing-box does not support {proto}")
    if node.spider_x:
        raise UnsupportedOutbound("sing-box does not support Reality spider_x")
    if proto not in {"vmess", "vless", "trojan", "ss", "hysteria2", "tuic"}:
        raise UnsupportedOutbound(f"unsupported sing-box protocol: {proto}")
    _validate_credentials(node)

    output: dict = {
        "type": "shadowsocks" if proto == "ss" else proto,
        "tag": _base_name(node),
        "server": node.host,
        "server_port": node.port,
    }
    if proto == "vmess":
        output["uuid"] = node.uuid
        output["security"] = node.method or "auto"
        output["alter_id"] = node.alter_id if node.alter_id is not None else 0
    elif proto == "vless":
        output["uuid"] = node.uuid
        if node.flow:
            output["flow"] = node.flow
        if node.packet_encoding:
            output["packet_encoding"] = node.packet_encoding
    elif proto in {"trojan", "hysteria2"}:
        output["password"] = node.password
    elif proto == "ss":
        output.update({"method": node.method, "password": node.password})
    elif proto == "tuic":
        output.update({"uuid": node.uuid, "password": node.password})
        if node.congestion_control:
            output["congestion_control"] = node.congestion_control
        if node.udp_relay_mode:
            output["udp_relay_mode"] = node.udp_relay_mode

    if proto == "hysteria2" and node.obfs:
        obfs: dict = {"type": node.obfs}
        if node.obfs_param:
            obfs["password"] = node.obfs_param
        output["obfs"] = obfs
    _add_singbox_transport(output, node)
    tls = _singbox_tls(node)
    if tls is not None:
        output["tls"] = tls
    return output


def _unique_name(base: str, seen: set[str]) -> str:
    if base not in seen:
        seen.add(base)
        return base
    suffix = 2
    while f"{base}-{suffix}" in seen:
        suffix += 1
    unique = f"{base}-{suffix}"
    seen.add(unique)
    return unique


def emit_clash(nodes: list[ProxyNode]) -> dict:
    proxies: list[dict] = []
    seen_names: set[str] = set()
    for node in nodes:
        proxy = to_clash_dict(node)
        proxy["name"] = _unique_name(str(proxy["name"]), seen_names)
        proxies.append(proxy)
    return {"proxies": proxies}


def clash_skip_reason(node: ProxyNode) -> str | None:
    """Return why the pinned Clash verifier cannot represent this node."""

    if node.proto.lower() == "juicity":
        return "protocol:juicity"
    return None


def _singbox_skip_reason(node: ProxyNode) -> str | None:
    proto = node.proto.lower()
    if proto in {"ssr", "juicity"}:
        return f"protocol:{proto}"
    if (node.net or "").lower() == "xhttp":
        return "transport:xhttp"
    if node.spider_x:
        return "reality:spider-x"
    return None


def emit_singbox(nodes: list[ProxyNode]) -> dict:
    outbounds: list[dict] = []
    seen_tags: set[str] = set()
    for node in nodes:
        if _singbox_skip_reason(node):
            continue
        outbound = to_singbox_outbound(node)
        outbound["tag"] = _unique_name(str(outbound["tag"]), seen_tags)
        outbounds.append(outbound)
    return {"outbounds": outbounds}


def emit_v2ray_b64(nodes: list[ProxyNode]) -> str:
    uris: list[str] = []
    for node in nodes:
        validate_proxy_node(node)
        if node.raw:
            validate_node_raw(node)
            uris.append(node.raw)
            continue
        uris.append(node_to_uri(node))
    return base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")


def _fmt_speed(download_speed: float | None) -> str:
    if download_speed is None:
        return "n/a"
    try:
        return f"{float(download_speed):.1f}MB/s"
    except (TypeError, ValueError):
        return "n/a"


def _node_title(node: ProxyNode) -> str:
    return f"{_base_name(node)} - {_fmt_speed(_download_speed(node))}"


def _node_description(node: ProxyNode) -> str:
    return ", ".join(
        (
            f"proto={node.proto}",
            f"host={node.host}",
            f"port={node.port}",
            f"latency={node.latency_ms if node.latency_ms is not None else 'n/a'}ms",
            f"download_speed={_fmt_speed(_download_speed(node))}",
        )
    )


def _rfc822_now() -> str:
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def emit_rss(nodes: list[ProxyNode]) -> str:
    pub_date = _rfc822_now()
    items: list[str] = []
    for node in nodes:
        items.append(
            "    <item>\n"
            f"      <title>{saxutils.escape(_node_title(node))}</title>\n"
            f"      <description>{saxutils.escape(_node_description(node))}</description>\n"
            f"      <link>{saxutils.escape(node.raw or '')}</link>\n"
            f'      <guid isPermaLink="false">{saxutils.escape(node.dedup_key())}</guid>\n'
            f"      <pubDate>{pub_date}</pubDate>\n"
            "    </item>"
        )
    items_block = "\n".join(items)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        "  <channel>\n"
        "    <title>proxy-aggregator alive nodes</title>\n"
        f"    <link>{saxutils.escape(os.environ.get('PUBLIC_BASE_URL', 'https://proxy-sub-aggregator.proxy-aggregator.workers.dev'))}</link>\n"
        "    <description>Verified proxy nodes sorted by download speed.</description>\n"
        "    <language>en</language>\n"
        f"    <pubDate>{pub_date}</pubDate>\n"
        f"    <lastBuildDate>{pub_date}</lastBuildDate>\n"
        "    <ttl>30</ttl>\n"
        "    <generator>free-proxy aggregator</generator>\n"
        f"{items_block}\n"
        "  </channel>\n"
        "</rss>\n"
    )
    return xml


def _replace_snapshot(rendered: dict[Path, str]) -> None:
    """Activate a group of text files and restore every prior file on failure."""

    temporary: dict[Path, Path] = {}
    originals: dict[Path, bytes | None] = {}
    replaced: list[Path] = []
    try:
        # Render and fsync-equivalent close every temporary file before the
        # first public destination changes.
        for destination, content in rendered.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            tmp = destination.with_suffix(destination.suffix + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            temporary[destination] = tmp
            originals[destination] = (
                destination.read_bytes() if destination.exists() else None
            )
        for destination, tmp in temporary.items():
            tmp.replace(destination)
            replaced.append(destination)
    except Exception as exc:
        recovery_errors: list[str] = []
        for destination in reversed(replaced):
            try:
                previous = originals[destination]
                if previous is None:
                    destination.unlink(missing_ok=True)
                else:
                    restore = destination.with_suffix(destination.suffix + ".restore")
                    restore.write_bytes(previous)
                    restore.replace(destination)
            except Exception as recovery_exc:  # pragma: no cover - catastrophic I/O
                recovery_errors.append(f"{destination.name}: {recovery_exc}")
        suffix = (
            f"; recovery errors: {'; '.join(recovery_errors)}"
            if recovery_errors
            else ""
        )
        raise RuntimeError(f"output snapshot activation failed: {exc}{suffix}") from exc
    finally:
        for tmp in temporary.values():
            tmp.unlink(missing_ok=True)


def emit_all(
    *, include_unverified: bool = False, verify_summary: dict | None = None
) -> dict:
    """Render and transactionally activate a subscription snapshot.

    ``verify_summary`` is supplied only by the fail-closed CLI pipeline.  When
    present, the sanitized public status joins the same rollback group as the
    four subscription files.  Library callers that only render fixtures do not
    implicitly claim that a complete verification run occurred.
    """

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        all_nodes = load_live_nodes()
        nodes = sort_nodes(
            filter_alive(all_nodes, include_unverified=include_unverified)
        )
    except InvalidLiveSnapshot as exc:
        return {
            "nodes": 0,
            "clash_proxies": 0,
            "singbox_outbounds": 0,
            "rss_items": 0,
            "success": False,
            "error": str(exc),
        }
    if not nodes:
        return {
            "nodes": 0,
            "clash_proxies": 0,
            "singbox_outbounds": 0,
            "rss_items": 0,
            "success": False,
            "error": "no verified nodes; existing output snapshot retained",
        }
    try:
        clash = emit_clash(nodes)
        singbox = emit_singbox(nodes)
        v2ray = emit_v2ray_b64(nodes)
        rss = emit_rss(nodes)
    except (TypeError, ValueError) as exc:
        return {
            "nodes": len(nodes),
            "clash_proxies": 0,
            "singbox_outbounds": 0,
            "rss_items": 0,
            "success": False,
            "error": f"output conversion failed: {exc}",
        }

    singbox_skipped: dict[str, int] = {}
    for node in nodes:
        reason = _singbox_skip_reason(node)
        if reason:
            singbox_skipped[reason] = singbox_skipped.get(reason, 0) + 1
    expected_singbox = len(nodes) - sum(singbox_skipped.values())
    if (
        len(clash["proxies"]) != len(nodes)
        or len(singbox["outbounds"]) != expected_singbox
    ):
        return {
            "nodes": len(nodes),
            "clash_proxies": len(clash["proxies"]),
            "singbox_outbounds": len(singbox["outbounds"]),
            "rss_items": 0,
            "success": False,
            "error": "output conversion count mismatch; existing snapshot retained",
        }
    rendered = {
        OUTPUT_DIR / "clash.yaml": yaml.safe_dump(
            clash, allow_unicode=True, sort_keys=False
        ),
        OUTPUT_DIR / "singbox.json": json.dumps(singbox, ensure_ascii=False, indent=2)
        + "\n",
        OUTPUT_DIR / "v2ray-base64.txt": v2ray,
        FEED_FILE: rss,
    }
    try:
        if verify_summary is not None:
            if include_unverified:
                raise InvalidPipelineStatus(
                    "public pipeline status cannot include unverified nodes"
                )
            expected_hash = verify_summary.get("live_snapshot_sha256")
            actual_hash = hashlib.sha256(LIVE_FILE.read_bytes()).hexdigest()
            if (
                not isinstance(expected_hash, str)
                or len(expected_hash) != 64
                or expected_hash != actual_hash
            ):
                raise InvalidPipelineStatus(
                    "verify metadata does not match the current live snapshot"
                )
            status = _pipeline_status_document(
                all_nodes,
                verify_summary=verify_summary,
                clash_proxies=len(clash["proxies"]),
                singbox_outbounds=len(singbox["outbounds"]),
                rss_items=len(nodes),
            )
        else:
            status = _unknown_pipeline_status_document(
                all_nodes,
                node_count=len(nodes),
                clash_proxies=len(clash["proxies"]),
                singbox_outbounds=len(singbox["outbounds"]),
                rss_items=len(nodes),
            )
    except InvalidPipelineStatus as exc:
        return {
            "nodes": len(nodes),
            "clash_proxies": len(clash["proxies"]),
            "singbox_outbounds": len(singbox["outbounds"]),
            "rss_items": len(nodes),
            "success": False,
            "error": f"pipeline status validation failed: {exc}",
        }
    rendered[OUTPUT_DIR / "pipeline-status.json"] = (
        json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    try:
        _replace_snapshot(rendered)
    except RuntimeError as exc:
        return {
            "nodes": len(nodes),
            "clash_proxies": len(clash["proxies"]),
            "singbox_outbounds": len(singbox["outbounds"]),
            "rss_items": len(nodes),
            "success": False,
            "error": str(exc),
        }

    summary = {
        "nodes": len(nodes),
        "clash_proxies": len(clash["proxies"]),
        "singbox_outbounds": len(singbox["outbounds"]),
        "rss_items": len(nodes),
        "success": True,
    }
    summary["pipeline_status"] = status["pipeline_status"]
    if singbox_skipped:
        summary["singbox_skipped"] = singbox_skipped
    return summary


if __name__ == "__main__":
    print(json.dumps(emit_all(), ensure_ascii=False, indent=2))
