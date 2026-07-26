from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

from src.aggregator import gray_sources


class _Response:
    def __init__(self, status_code: int, payload=None, *, text: str = "", headers=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._payload


class _DiscoveryAndPanelClient:
    """Small in-process transport covering all G1 HTTP contracts."""

    calls: list[tuple[str, str, dict]] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if url == "https://api.shodan.io/shodan/host/search":
            return _Response(
                200,
                {
                    "matches": [
                        {
                            "ip_str": "198.51.100.10",
                            "port": "443",
                            "http": {"html": "<title>V2Board</title>"},
                        }
                    ]
                },
            )
        if url == "https://fofa.info/api/v1/search/all":
            return _Response(
                200,
                {"results": [["https://fofa.example:8443", "203.0.113.11", "8443"]]},
            )
        if url == "https://approved.example:443/api/v1/user/getSubscribe":
            return _Response(200, {"data": {"subscribe_url": "/sub/unpadded"}})
        if url == "https://approved.example:443/sub/unpadded":
            content = (
                "vless://id@edge.example:443?encryption=none\n"
                "trojan://secret@edge.example:443?security=tls\n"
                "vless://id@edge.example:443?encryption=none\n"
            )
            encoded = base64.urlsafe_b64encode(content.encode()).decode().rstrip("=")
            return _Response(200, text=encoded)
        return _Response(404, {})

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if url == gray_sources.QUAKE_SEARCH_URL:
            return _Response(
                200,
                {
                    "data": [
                        {
                            "ip": "203.0.113.12",
                            "port": "2053",
                            "service": {"http": {"body": "Xboard"}},
                        }
                    ]
                },
            )
        if url == "https://approved.example:443/api/v1/passport/auth/register":
            return _Response(200, {"data": {"auth_data": "Bearer approved-token"}})
        return _Response(404, {})


def _patch_state(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(gray_sources, "STATE_DIR", tmp_path)
    monkeypatch.setattr(gray_sources, "GRAY_NODES_FILE", tmp_path / "gray_nodes.jsonl")
    monkeypatch.setattr(
        gray_sources, "PANEL_LEADS_FILE", tmp_path / "gray_panel_leads.jsonl"
    )
    monkeypatch.setattr(gray_sources, "LAST_RUN_FILE", tmp_path / "last-run.json")
    monkeypatch.setattr(
        gray_sources,
        "_validate_public_url",
        lambda _url: asyncio.sleep(0, result=(True, "ok")),
    )


def test_g1_discovery_to_approved_registration_and_quarantine(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)
    _DiscoveryAndPanelClient.calls = []
    monkeypatch.setattr(gray_sources.httpx, "AsyncClient", _DiscoveryAndPanelClient)
    monkeypatch.setattr(
        gray_sources,
        "load_config",
        lambda: {
            "shodan_api_key": "shodan-secret",
            "fofa_email": "ops@example.net",
            "fofa_key": "fofa-secret",
            "quake_key": "quake-secret",
            "shodan_queries": ["v2board"],
            "fofa_queries": ["app=V2Board"],
            "quake_queries": ["app:Xboard"],
            "rate_limit_seconds": 0,
            "request_timeout_seconds": 1,
            "max_panel_attempts": 5,
            "panel_register": {
                "enabled": True,
                "approved_targets": [{"host": "approved.example", "port": 443}],
                "verify_tls": True,
                "default_email": "review@example.net",
                "default_password": "test-password",
                "register_path": "api/v1/passport/auth/register",
                "sub_path": "/api/v1/user/getSubscribe",
            },
        },
    )
    (tmp_path / "last-run.json").write_text(
        json.dumps({"stages": {"prior": {"counts": {"ok": 1}}}}), encoding="utf-8"
    )

    summary = asyncio.run(gray_sources._run_async())

    assert summary["success"] is True
    assert summary["shodan_hits"] == 1
    assert summary["fofa_hits"] == 1
    assert summary["quake_hits"] == 1
    assert summary["panels_found"] == 3
    assert summary["leads_written"] == 3
    assert summary["approved_targets"] == 1
    assert summary["panels_registered"] == 1
    assert summary["nodes_collected"] == 2
    assert summary["skipped_no_key"] == []

    leads = [
        json.loads(line)
        for line in (tmp_path / "gray_panel_leads.jsonl").read_text().splitlines()
    ]
    assert {(row["host"], row["port"]) for row in leads} == {
        ("198.51.100.10", 443),
        ("fofa.example", 8443),
        ("203.0.113.12", 2053),
    }
    assert all(row["approved"] is False for row in leads)

    records = [
        json.loads(line)
        for line in (tmp_path / "gray_nodes.jsonl").read_text().splitlines()
    ]
    assert [row["raw"] for row in records] == [
        "vless://id@edge.example:443?encryption=none",
        "trojan://secret@edge.example:443?security=tls",
    ]
    assert all(
        row["enabled"] is False
        and row["watermark_suspect"] is True
        and row["review_status"] == "pending"
        for row in records
    )

    register_urls = [
        url
        for method, url, _kwargs in _DiscoveryAndPanelClient.calls
        if method == "POST" and "register" in url
    ]
    assert register_urls == [
        "https://approved.example:443/api/v1/passport/auth/register"
    ]
    subscribe_call = next(
        (
            item
            for item in _DiscoveryAndPanelClient.calls
            if item[1].endswith("getSubscribe")
        ),
        None,
    )
    assert subscribe_call is not None
    assert subscribe_call[2]["headers"]["Authorization"] == "Bearer approved-token"

    last_run = json.loads((tmp_path / "last-run.json").read_text())
    assert last_run["last_stage_cmd"] == "gray-crawl"
    assert last_run["counts"] == {"gray-crawl": summary}
    assert "prior" in last_run["stages"]
    assert last_run["stages"]["gray"]["counts"] == summary


def test_g1_discovery_leads_never_register_without_explicit_approval(
    monkeypatch, tmp_path
):
    _patch_state(monkeypatch, tmp_path)
    _DiscoveryAndPanelClient.calls = []
    monkeypatch.setattr(gray_sources.httpx, "AsyncClient", _DiscoveryAndPanelClient)
    monkeypatch.setattr(
        gray_sources,
        "load_config",
        lambda: {
            "shodan_api_key": "key",
            "shodan_queries": ["v2board"],
            "fofa_queries": [],
            "quake_queries": [],
            "rate_limit_seconds": 0,
            "panel_register": {"enabled": False, "approved_targets": []},
        },
    )

    summary = asyncio.run(gray_sources._run_async())

    assert summary["success"] is True
    assert summary["panels_found"] == 1
    assert summary["leads_written"] == 1
    assert summary["approved_targets"] == 0
    assert summary["panels_registered"] == 0
    assert summary["nodes_collected"] == 0
    assert not any(
        method == "POST" and "register" in url
        for method, url, _kwargs in _DiscoveryAndPanelClient.calls
    )
    assert (tmp_path / "gray_nodes.jsonl").exists()


def test_g1_decodes_unpadded_urlsafe_subscription_blob():
    text = "vless://id@example.net:443?encryption=none\n"
    encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    assert gray_sources._decode_subscription_blob(encoded) == text


def test_g1_run_deadline_writes_failed_canonical_state(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)

    async def slow_search(*_args, **_kwargs):
        await asyncio.sleep(2)
        return []

    monkeypatch.setattr(
        gray_sources,
        "load_config",
        lambda: {
            "shodan_api_key": "fixture",
            "shodan_queries": ["slow"],
            "fofa_queries": [],
            "quake_queries": [],
            "max_run_seconds": 1,
            "request_timeout_seconds": 5,
            "rate_limit_seconds": 0,
            "panel_register": {"enabled": False, "approved_targets": []},
        },
    )
    monkeypatch.setattr(gray_sources, "_shodan_search", slow_search)

    summary = asyncio.run(gray_sources._run_async())

    assert summary["success"] is False
    assert summary["reason"] == "timeout"
    last_run = json.loads((tmp_path / "last-run.json").read_text())
    assert last_run["last_stage_cmd"] == "gray-crawl"
    assert last_run["counts"]["gray-crawl"]["error"].startswith("gray-crawl exceeded")
