from __future__ import annotations

import base64
import json

import pytest
import yaml

from src.aggregator.dedupe import content_hash, dedupe_nodes, node_dedup_key
from src.aggregator.emit import (
    UnsupportedOutbound,
    emit_clash,
    emit_singbox,
    filter_alive,
    to_clash_dict,
    to_singbox_outbound,
)
from src.aggregator.models import ProxyNode
from src.aggregator.parser import (
    extract_uris,
    node_to_uri,
    parse_clash_yaml,
    parse_singbox_json,
    parse_uri,
)


UUID = "12345678-1234-1234-1234-123456789abc"
UUID2 = "22345678-1234-1234-1234-123456789abc"
UUID3 = "32345678-1234-1234-1234-123456789abc"


def vless_node(**updates) -> ProxyNode:
    values = {
        "proto": "vless",
        "host": "edge.example.com",
        "port": 443,
        "uuid": UUID,
        "sni": "origin.example.com",
        "net": "ws",
        "path": "/ws?ed=2048",
        "host_header": "cdn.example.com",
        "security": "reality",
        "tls": True,
        "fp": "chrome",
        "utls": True,
        "pbk": "PUBLIC_KEY",
        "sid": "0123abcd",
        "skip_cert_verify": False,
        "raw": "vless://fixture",
        "name": "edge",
    }
    values.update(updates)
    return ProxyNode(**values)


def test_vless_reality_uri_round_trip_without_double_encoding() -> None:
    uri = (
        f"vless://{UUID}@edge.example.com:443?security=reality&type=ws"
        "&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=origin.example.com"
        "&flow=xtls-rprx-vision&fp=chrome&pbk=PUBLIC_KEY&sid=0123abcd"
        "&allowInsecure=0#edge"
    )

    node = parse_uri(uri)
    assert node is not None
    assert node.uuid == UUID
    assert node.password is None
    assert node.path == "/ws?ed=2048"
    assert node.security == "reality"
    assert node.tls is True
    assert node.skip_cert_verify is False

    rebuilt = node_to_uri(node)
    assert "security=reality" in rebuilt
    assert "path=%2Fws%3Fed%3D2048" in rebuilt
    assert "%252F" not in rebuilt
    reparsed = parse_uri(rebuilt)
    assert reparsed is not None
    assert reparsed.path == node.path
    assert reparsed.security == "reality"
    assert reparsed.flow == "xtls-rprx-vision"


def test_protocol_specific_uri_credentials() -> None:
    trojan = parse_uri("trojan://p%40ss%3Aword@host.example:443?sni=host.example")
    assert trojan is not None
    assert trojan.uuid is None
    assert trojan.password == "p@ss:word"

    tuic = parse_uri(
        f"tuic://{UUID}:p%40ss@host.example:443?sni=host.example"
        "&congestion_control=bbr&udp_relay_mode=native"
    )
    assert tuic is not None
    assert tuic.uuid == UUID
    assert tuic.password == "p@ss"
    assert tuic.congestion_control == "bbr"
    assert tuic.udp_relay_mode == "native"
    rebuilt = node_to_uri(tuic)
    assert f"{UUID}:p%40ss@" in rebuilt
    assert "security=tls" in rebuilt
    reparsed = parse_uri(rebuilt)
    assert reparsed is not None
    assert reparsed.dedup_key() == tuic.dedup_key()

    juicity = parse_uri(
        f"juicity://{UUID2}:secret@host.example:443?sni=host.example"
        "&congestion_control=cubic"
    )
    assert juicity is not None
    assert juicity.uuid == UUID2
    assert juicity.password == "secret"


def test_shadowsocks_requires_and_preserves_method() -> None:
    node = parse_uri("ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example:8388#ss")
    assert node is not None
    assert node.method == "aes-256-gcm"
    assert node.password == "secret"
    assert parse_uri("ss://password@ss.example:8388") is None
    assert (
        parse_uri(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example:8388?plugin=v2ray-plugin%3Btls"
        )
        is None
    )

    missing_method = ProxyNode(
        proto="ss",
        host="ss.example",
        port=8388,
        password="secret",
        raw="ss://invalid",
    )
    with pytest.raises(UnsupportedOutbound, match="Shadowsocks"):
        emit_clash([missing_method])
    with pytest.raises(UnsupportedOutbound, match="Shadowsocks"):
        emit_singbox([missing_method])


def test_ssr_round_trip_and_clash_shape() -> None:
    original = ProxyNode(
        proto="ssr",
        host="ssr.example",
        port=8443,
        password="secret:with-colon",
        method="aes-256-cfb",
        protocol="auth_aes128_md5",
        protocol_param="user:token",
        obfs="tls1.2_ticket_auth",
        obfs_param="cdn.example.com",
        raw="",
        name="SSR node",
    )
    parsed = parse_uri(node_to_uri(original))
    assert parsed is not None
    for field in (
        "host",
        "port",
        "password",
        "method",
        "protocol",
        "protocol_param",
        "obfs",
        "obfs_param",
        "name",
    ):
        assert getattr(parsed, field) == getattr(original, field)

    clash = to_clash_dict(parsed)
    assert clash["type"] == "ssr"
    assert clash["protocol-param"] == "user:token"
    assert clash["obfs-param"] == "cdn.example.com"
    assert emit_singbox([parsed]) == {"outbounds": []}


def test_clash_ws_reality_schema_and_no_top_level_path() -> None:
    proxy = to_clash_dict(vless_node())
    assert proxy["tls"] is True
    assert proxy["servername"] == "origin.example.com"
    assert proxy["skip-cert-verify"] is False
    assert proxy["ws-opts"] == {
        "path": "/ws?ed=2048",
        "headers": {"Host": "cdn.example.com"},
    }
    assert proxy["reality-opts"] == {
        "public-key": "PUBLIC_KEY",
        "short-id": "0123abcd",
    }
    assert "path" not in proxy
    assert "headers" not in proxy
    assert "password" not in proxy


def test_clash_grpc_options_and_parser() -> None:
    text = yaml.safe_dump(
        {
            "proxies": [
                {
                    "name": "grpc",
                    "type": "vless",
                    "server": "grpc.example",
                    "port": 443,
                    "uuid": UUID,
                    "network": "grpc",
                    "grpc-opts": {"grpc-service-name": "tunnel"},
                    "tls": True,
                    "servername": "sni.example",
                    "skip-cert-verify": False,
                }
            ]
        }
    )
    nodes = parse_clash_yaml(text)
    assert len(nodes) == 1
    node = nodes[0]
    assert node.net == "grpc"
    assert node.path == "tunnel"
    assert node.sni == "sni.example"
    assert node.tls is True
    assert node.skip_cert_verify is False
    emitted = to_clash_dict(node)
    assert emitted["grpc-opts"] == {"grpc-service-name": "tunnel"}
    assert "path" not in emitted


def test_singbox_transport_tls_utls_reality_and_flow_schema() -> None:
    node = vless_node(flow="xtls-rprx-vision", skip_cert_verify=True)
    outbound = to_singbox_outbound(node)
    assert outbound["flow"] == "xtls-rprx-vision"
    assert outbound["transport"] == {
        "type": "ws",
        "path": "/ws?ed=2048",
        "headers": {"Host": "cdn.example.com"},
    }
    assert "network" not in outbound
    assert "password" not in outbound
    assert outbound["tls"] == {
        "enabled": True,
        "server_name": "origin.example.com",
        "insecure": True,
        "utls": {"enabled": True, "fingerprint": "chrome"},
        "reality": {
            "enabled": True,
            "public_key": "PUBLIC_KEY",
            "short_id": "0123abcd",
        },
    }


def test_singbox_parser_round_trip_schema() -> None:
    document = {
        "outbounds": [
            {
                "type": "vless",
                "tag": "parsed",
                "server": "edge.example",
                "server_port": 443,
                "uuid": UUID,
                "flow": "xtls-rprx-vision",
                "transport": {
                    "type": "grpc",
                    "service_name": "tunnel",
                },
                "tls": {
                    "enabled": True,
                    "server_name": "sni.example",
                    "insecure": False,
                    "alpn": ["h2", "http/1.1"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": "PUBLIC",
                        "short_id": "abcd",
                    },
                },
            }
        ]
    }
    nodes = parse_singbox_json(json.dumps(document))
    assert len(nodes) == 1
    node = nodes[0]
    assert node.net == "grpc"
    assert node.path == "tunnel"
    assert node.alpn == "h2,http/1.1"
    assert node.security == "reality"
    assert node.skip_cert_verify is False
    rebuilt = to_singbox_outbound(node)
    assert rebuilt["transport"] == {"type": "grpc", "service_name": "tunnel"}
    assert rebuilt["tls"]["enabled"] is True
    assert rebuilt["tls"]["alpn"] == ["h2", "http/1.1"]


def test_tuic_and_juicity_client_shapes() -> None:
    tuic = ProxyNode(
        proto="tuic",
        host="tuic.example",
        port=443,
        uuid=UUID,
        password="secret",
        sni="tuic.example",
        alpn="h3",
        congestion_control="bbr",
        udp_relay_mode="native",
        raw="tuic://fixture",
    )
    clash = to_clash_dict(tuic)
    assert clash["congestion-controller"] == "bbr"
    assert clash["udp-relay-mode"] == "native"
    singbox = to_singbox_outbound(tuic)
    assert singbox["uuid"] == UUID
    assert singbox["password"] == "secret"
    assert singbox["congestion_control"] == "bbr"
    assert singbox["tls"]["enabled"] is True

    juicity = tuic.model_copy(update={"proto": "juicity", "raw": "juicity://fixture"})
    with pytest.raises(UnsupportedOutbound, match="unsupported Clash protocol"):
        to_clash_dict(juicity)
    assert emit_singbox([juicity]) == {"outbounds": []}


def test_emitters_make_duplicate_names_and_tags_unique() -> None:
    first = vless_node(name="same")
    second = vless_node(
        name="same",
        uuid=UUID2,
        raw=f"vless://{UUID2}@edge.example.com:443",
    )
    clash = emit_clash([first, second])["proxies"]
    singbox = emit_singbox([first, second])["outbounds"]
    assert [item["name"] for item in clash] == ["same", "same-2"]
    assert [item["tag"] for item in singbox] == ["same", "same-2"]


def test_emitters_normalize_display_name_whitespace() -> None:
    named = vless_node(name="  display\t\nname  ")
    unnamed = vless_node(
        name=" \t ",
        uuid=UUID2,
        raw=f"vless://{UUID2}@edge.example.com:443",
    )

    clash = emit_clash([named, unnamed])["proxies"]
    singbox = emit_singbox([named, unnamed])["outbounds"]

    assert [item["name"] for item in clash] == [
        "display name",
        "vless-edge.example.com:443",
    ]
    assert [item["tag"] for item in singbox] == [
        "display name",
        "vless-edge.example.com:443",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("password", "different"),
        ("method", "auto"),
        ("path", "/different"),
        ("host_header", "different.example"),
        ("flow", "xtls-rprx-vision"),
        ("packet_encoding", "xudp"),
        ("fp", "firefox"),
        ("alpn", "h2"),
        ("pbk", "OTHER_KEY"),
        ("sid", "ffff"),
        ("spider_x", "/spider"),
        ("security", "tls"),
        ("tls", False),
        ("utls", False),
        ("skip_cert_verify", True),
        ("protocol", "auth_sha1_v4"),
        ("protocol_param", "param"),
        ("obfs", "salamander"),
        ("obfs_param", "obfs-secret"),
        ("congestion_control", "bbr"),
        ("udp_relay_mode", "native"),
    ],
)
def test_dedup_key_includes_every_connection_semantic(field: str, value) -> None:
    original = vless_node()
    changed = original.model_copy(update={field: value})
    assert node_dedup_key(original) != node_dedup_key(changed)


def test_raw_uri_comparison_is_case_sensitive() -> None:
    first = vless_node(raw="VLESS://TOKEN", path="/one")
    second = vless_node(raw="vless://token", path="/two")
    unique, dropped = dedupe_nodes([first, second])
    assert unique == [first, second]
    assert dropped == []


def test_content_hash_is_order_and_duplicate_independent() -> None:
    first = vless_node()
    second = vless_node(uuid=UUID2, raw=f"vless://{UUID2}@edge.example.com:443")
    assert content_hash([first, second]) == content_hash([second, first, first])


def test_publish_filter_requires_alive_unless_explicitly_overridden() -> None:
    verified = vless_node(alive=True)
    unverified = vless_node(alive=None, uuid=UUID2)
    dead = vless_node(alive=False, uuid=UUID3)
    assert filter_alive([verified, unverified, dead]) == [verified]
    assert filter_alive([verified, unverified, dead], include_unverified=True) == [
        verified,
        unverified,
    ]


def _vmess_uri(**updates) -> str:
    payload = {
        "v": "2",
        "ps": "vmess",
        "add": "vmess.example",
        "port": "443",
        "id": UUID,
        "aid": "2",
        "scy": "auto",
        "net": "httpupgrade",
        "host": "cdn.example",
        "path": "/upgrade",
        "tls": "tls",
        "sni": "origin.example",
    }
    payload.update(updates)
    encoded = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()
    return f"vmess://{encoded}"


def test_vmess_alter_id_and_httpupgrade_round_trip() -> None:
    node = parse_uri(_vmess_uri())
    assert node is not None
    assert node.alter_id == 2
    assert node.net == "httpupgrade"

    clash = to_clash_dict(node)
    assert clash["alterId"] == 2
    assert clash["http-upgrade-opts"] == {
        "path": "/upgrade",
        "host": "cdn.example",
    }
    singbox = to_singbox_outbound(node)
    assert singbox["alter_id"] == 2
    assert singbox["transport"] == {
        "type": "httpupgrade",
        "path": "/upgrade",
        "host": "cdn.example",
    }

    reparsed = parse_uri(node_to_uri(node))
    assert reparsed is not None
    assert reparsed.alter_id == 2
    assert reparsed.net == "httpupgrade"

    changed = node.model_copy(update={"alter_id": 0})
    assert node_dedup_key(node) != node_dedup_key(changed)


def test_xhttp_is_native_in_clash_and_explicitly_unsupported_in_singbox() -> None:
    node = parse_uri(_vmess_uri(net="xhttp", type="packet-up", path="/xhttp"))
    assert node is not None
    assert node.transport_mode == "packet-up"
    clash = to_clash_dict(node)
    assert clash["network"] == "xhttp"
    assert clash["xhttp-opts"] == {
        "path": "/xhttp",
        "host": "cdn.example",
        "mode": "packet-up",
    }
    with pytest.raises(UnsupportedOutbound, match="xhttp"):
        to_singbox_outbound(node)
    assert emit_singbox([node]) == {"outbounds": []}


def test_vmess_tcp_http_header_and_insecure_alias_are_preserved() -> None:
    node = parse_uri(
        _vmess_uri(
            net="tcp",
            type="http",
            path="/header",
            **{"skip-cert-verify": True},
        )
    )
    assert node is not None
    assert node.net == "http"
    assert node.skip_cert_verify is True
    clash = to_clash_dict(node)
    assert clash["network"] == "http"
    assert clash["http-opts"] == {
        "method": "GET",
        "path": ["/header"],
        "headers": {"Host": ["cdn.example"]},
    }
    singbox = to_singbox_outbound(node)
    assert singbox["transport"] == {
        "type": "http",
        "path": "/header",
        "host": ["cdn.example"],
    }
    reparsed = parse_uri(node_to_uri(node))
    assert reparsed is not None
    assert reparsed.net == "http"
    assert reparsed.skip_cert_verify is True


def test_uri_extraction_preserves_encoded_fragment_name() -> None:
    uri = "trojan://secret@edge.example:443?security=tls#node-%F0%9F%87%B9%F0%9F%87%BC"
    assert extract_uris(f"prefix {uri} suffix") == [uri]
    node = parse_uri(extract_uris(uri)[0])
    assert node is not None
    assert node.name == "node-🇹🇼"


@pytest.mark.parametrize(
    "uri",
    [
        "vless://@edge.example:443",
        "trojan://@edge.example:443",
        f"tuic://{UUID}@edge.example:443",
        "hysteria2://@edge.example:443",
        _vmess_uri(id=""),
    ],
)
def test_parse_boundary_rejects_missing_credentials(uri: str) -> None:
    assert parse_uri(uri) is None


@pytest.mark.parametrize(
    "uri",
    [
        f"vless://{UUID}@edge.example:443?security=bogus",
        "vless://not-a-uuid@edge.example:443?security=tls",
        "trojan://secret@edge.example:443?security=none",
        "hysteria2://secret@edge.example:443?security=none",
        f"tuic://{UUID}:secret@edge.example:443?security=none",
        f"juicity://{UUID}:secret@edge.example:443?security=none",
        f"vless://{UUID}@edge.example:443?type=xhttp&mode=unknown",
        f"vless://{UUID}@edge.example:443?type=grpc&mode=multi",
        f"vless://{UUID}@edge.example:443?type=grpc&mode=gun&authority=other",
        f"vless://{UUID}@edge.example:443?security=tls&ech=config",
        f"vless://{UUID}@edge.example:443?security=tls&fm=%7B%7D",
    ],
)
def test_parse_boundary_rejects_invalid_security_and_transport(uri: str) -> None:
    assert parse_uri(uri) is None


def test_xhttp_default_mode_round_trip_is_canonical() -> None:
    node = parse_uri(f"vless://{UUID}@edge.example:443?security=tls&type=xhttp")
    assert node is not None
    assert node.transport_mode == "auto"
    reparsed = parse_uri(node_to_uri(node))
    assert reparsed is not None
    assert reparsed.transport_mode == "auto"
    assert reparsed.dedup_key() == node.dedup_key()


def test_vless_packet_encoding_and_reality_spider_x_are_preserved() -> None:
    uri = (
        f"vless://{UUID}@edge.example:443?security=reality&type=tcp"
        "&pbk=1y5h2FGWKXTJ9xLPCqPo6Mw7RxoZzh6fGkEQKNxpZ3s"
        "&sid=abcd&spx=%2Freality&packetEncoding=xudp"
    )
    node = parse_uri(uri)
    assert node is not None
    assert node.packet_encoding == "xudp"
    assert node.spider_x == "/reality"
    clash = to_clash_dict(node)
    assert clash["packet-encoding"] == "xudp"
    assert clash["reality-opts"]["spider-x"] == "/reality"
    with pytest.raises(UnsupportedOutbound, match="spider_x"):
        to_singbox_outbound(node)
    rebuilt = node_to_uri(node)
    assert "packetEncoding=xudp" in rebuilt
    assert "spx=%2Freality" in rebuilt
    reparsed = parse_uri(rebuilt)
    assert reparsed is not None
    assert reparsed.dedup_key() == node.dedup_key()


def test_vless_packet_encoding_maps_to_singbox() -> None:
    node = parse_uri(
        f"vless://{UUID}@edge.example:443?security=tls&packetEncoding=xudp"
    )
    assert node is not None
    assert to_singbox_outbound(node)["packet_encoding"] == "xudp"


def test_explicit_blank_security_stays_plaintext_despite_fingerprint() -> None:
    node = parse_uri(f"vless://{UUID}@edge.example:443?security=&type=tcp&fp=firefox")
    assert node is not None
    assert node.security == "none"
    assert node.tls is False
    assert node.fp is None
    rebuilt = node_to_uri(node)
    assert "security=none" in rebuilt
    assert "fp=" not in rebuilt


def test_vless_tcp_http_header_is_normalized_and_plain_tcp_drops_inert_fields() -> None:
    http_node = parse_uri(
        f"vless://{UUID}@edge.example:80?type=tcp&headerType=http"
        "&path=%2Fheader&host=cdn.example"
    )
    assert http_node is not None
    assert http_node.net == "http"
    assert to_clash_dict(http_node)["http-opts"]["path"] == ["/header"]

    tcp_node = parse_uri(
        f"vless://{UUID}@edge.example:80?type=tcp&headerType=none"
        "&path=%2Finert&host=ignored.example"
    )
    assert tcp_node is not None
    assert tcp_node.net == "tcp"
    assert tcp_node.path is None
    assert tcp_node.host_header is None
