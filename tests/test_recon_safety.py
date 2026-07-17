from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from src.aggregator import ct_recon
from src.aggregator import github_dork
from src.aggregator import gray_sources
from src.aggregator import resin_publisher
from src.aggregator import scanner
from src.aggregator import tg_recon
from src.aggregator import v2board_recon


class _Response:
    def __init__(self, status_code: int, payload=None, headers=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text
        self.content = (
            text.encode() if text else (b"{}" if payload is not None else b"")
        )

    def json(self):
        return self._payload


def test_gray_publish_gate_is_fail_closed():
    uri = "vless://id@example.net:443"
    assert resin_publisher._extract_enabled_gray_uri(uri)[0] is None
    assert (
        resin_publisher._extract_enabled_gray_uri(
            json.dumps({"raw": uri, "enabled": False, "watermark_suspect": False})
        )[0]
        is None
    )
    assert (
        resin_publisher._extract_enabled_gray_uri(
            json.dumps({"raw": uri, "enabled": True, "watermark_suspect": True})
        )[0]
        is None
    )
    assert (
        resin_publisher._extract_enabled_gray_uri(
            json.dumps({"raw": uri, "enabled": True, "watermark_suspect": False})
        )[0]
        == uri
    )


def test_resin_refresh_failure_rolls_back_candidate_only(monkeypatch):
    deleted: list[str] = []
    monkeypatch.setattr(resin_publisher, "_config", lambda: ("http://resin", "token"))
    monkeypatch.setattr(
        resin_publisher,
        "_list_subscriptions",
        lambda _base, _token: [{"id": "old", "name": "pool"}],
    )
    monkeypatch.setattr(
        resin_publisher,
        "_delete_subscription",
        lambda _base, _token, sub_id: deleted.append(sub_id) or True,
    )
    responses = iter([_Response(201, {"id": "candidate"}), _Response(500)])
    monkeypatch.setattr(
        resin_publisher.httpx, "post", lambda *args, **kwargs: next(responses)
    )

    result = resin_publisher.publish_to_resin("pool", ["vless://id@example.net:443"])

    assert deleted == ["candidate"]
    assert result["subscription_id"] is None
    assert result["rolled_back"] is True
    assert "prior retained" in result["error"]


def test_public_url_validation_rejects_private_and_mixed_dns(monkeypatch):
    assert (
        asyncio.run(gray_sources._validate_public_url("http://127.0.0.1/x"))[0] is False
    )
    assert (
        asyncio.run(gray_sources._validate_public_url("http://169.254.169.254/x"))[0]
        is False
    )
    assert (
        asyncio.run(gray_sources._validate_public_url("https://user:pw@example.net"))[0]
        is False
    )

    monkeypatch.setattr(
        gray_sources.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.1", 443)),
        ],
    )
    allowed, reason = asyncio.run(
        gray_sources._validate_public_url("https://mixed.example/path?token=secret")
    )
    assert allowed is False
    assert reason == "non_public_destination"
    assert "secret" not in gray_sources._redact_url(
        "https://mixed.example/path?token=secret"
    )


def test_safe_get_revalidates_redirect_target(monkeypatch):
    monkeypatch.setattr(
        gray_sources.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )

    class Client:
        def __init__(self):
            self.urls: list[str] = []

        async def get(self, url, **kwargs):
            self.urls.append(url)
            return _Response(302, headers={"location": "http://127.0.0.1/latest"})

    client = Client()
    assert (
        asyncio.run(
            gray_sources._safe_get_public_url(
                client, "https://public.example/sub?token=secret"
            )
        )
        is None
    )
    assert client.urls == ["https://public.example/sub?token=secret"]


def test_panel_registration_is_opt_in():
    assert gray_sources._approved_panel_targets({}) == []
    assert (
        gray_sources._approved_panel_targets(
            {"panel_register": {"enabled": False, "approved_targets": ["a.example"]}}
        )
        == []
    )


def test_intelligence_clients_always_verify_tls(monkeypatch):
    created: list[dict] = []

    class Client:
        def __init__(self, **kwargs):
            created.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def no_hits(*args, **kwargs):
        return []

    monkeypatch.setattr(gray_sources, "load_config", lambda: {})
    monkeypatch.setattr(gray_sources.httpx, "AsyncClient", Client)
    monkeypatch.setattr(gray_sources, "_shodan_search", no_hits)
    monkeypatch.setattr(gray_sources, "_fofa_search", no_hits)
    monkeypatch.setattr(gray_sources, "_quake_search", no_hits)
    monkeypatch.setattr(gray_sources, "_append_panel_leads", lambda _panels: 0)
    monkeypatch.setattr(gray_sources, "_update_last_run", lambda _summary: None)

    asyncio.run(gray_sources._run_async())
    assert created[0]["verify"] is True
    assert created[0]["follow_redirects"] is False


def test_nmap_uses_only_discovered_ports_and_ignores_stale_output(
    monkeypatch, tmp_path: Path
):
    output = tmp_path / "scan.xml"
    output.write_text("stale", encoding="utf-8")
    monkeypatch.setattr(scanner, "NMAP_OUT", output)
    monkeypatch.setattr(scanner, "_nmap_available", lambda: True)
    captured: list[str] = []

    def fake_run(cmd, **kwargs):
        captured.extend(cmd)
        assert not output.exists()
        output.write_text(
            '<nmaprun><host><address addr="203.0.113.10"/>'
            '<ports><port protocol="tcp" portid="443">'
            '<state state="open"/><service name="https"/></port>'
            '<port protocol="tcp" portid="80"><state state="closed"/></port>'
            "</ports></host></nmaprun>",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    results = scanner.run_nmap([scanner.OpenPort("203.0.113.10", 443)])

    assert captured[captured.index("-p") + 1] == "443"
    assert [(item.host, item.port) for item in results] == [("203.0.113.10", 443)]


def test_scanner_defaults_to_leads_only():
    recovered, leads = scanner._reconstruct_nodes(
        [], [scanner.OpenPort("203.0.113.10", 8388)]
    )
    assert recovered == []
    assert leads[0]["recovered"] is False
    assert leads[0]["credential_guess"] is False


def test_securitytrails_history_schema(monkeypatch):
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "secret")
    monkeypatch.setattr(
        ct_recon.httpx,
        "get",
        lambda *args, **kwargs: _Response(
            200,
            {
                "records": [
                    {
                        "first_seen": "2024-01-02T03:04:05Z",
                        "values": [{"ip": "1.1.1.1"}, {"ip": "not-an-ip"}],
                    }
                ]
            },
        ),
    )
    records = ct_recon.query_securitytrails("example.net")
    assert len(records) == 1
    assert records[0]["ip"] == "1.1.1.1"
    assert records[0]["source"] == "securitytrails"


def test_ct_run_merges_prior_intelligence(monkeypatch, tmp_path: Path):
    output = tmp_path / "recon_intel.jsonl"
    prior = {
        "domain": "old.example",
        "subdomain": "api.old.example",
        "ip": None,
        "sni": "api.old.example",
        "source": "crt.sh",
        "first_seen": 1,
    }
    output.write_text(json.dumps(prior) + "\n", encoding="utf-8")
    monkeypatch.setattr(ct_recon, "OUT", output)
    monkeypatch.setattr(ct_recon, "STATE", tmp_path)
    monkeypatch.setattr(
        ct_recon,
        "_load_config",
        lambda: {"watch_domains": ["new.example"], "preserve_existing": True},
    )
    fresh = {
        "domain": "new.example",
        "subdomain": "api.new.example",
        "ip": None,
        "sni": "api.new.example",
        "source": "crt.sh",
        "first_seen": 2,
    }
    monkeypatch.setattr(ct_recon, "query_crtsh", lambda domain: [fresh])
    monkeypatch.setattr(ct_recon, "query_securitytrails", lambda domain: [])

    result = ct_recon.run()
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert {row["domain"] for row in rows} == {"old.example", "new.example"}
    assert result["preserved_previous"] is True
    assert result["new_records"] == 1


def test_v2board_prefers_ct_subdomain(monkeypatch, tmp_path: Path):
    intel = tmp_path / "intel.jsonl"
    intel.write_text(
        json.dumps(
            {
                "domain": "example.net",
                "subdomain": "panel.example.net",
                "sni": "panel.example.net",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(v2board_recon, "RECON_INTEL_FILE", intel)
    assert v2board_recon._load_recon_intel_hosts() == ["panel.example.net"]


def test_gh_cli_pagination_stops_on_empty_page(monkeypatch):
    monkeypatch.setattr(github_dork, "CODE_SEARCH_PER_PAGE", 2)
    monkeypatch.setattr(github_dork, "CODE_SEARCH_MAX_RESULTS", 10)
    monkeypatch.setattr(github_dork.time, "sleep", lambda _seconds: None)
    calls = 0

    def fake_run(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            lines = [
                json.dumps({"repo": "o/r", "path": f"p{i}", "html_url": "u"})
                for i in range(2)
            ]
            return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(github_dork.subprocess, "run", fake_run)
    assert len(github_dork._gh_search_one("query", False)) == 2
    assert calls == 2


def test_gitleaks_reads_explicit_json_report(monkeypatch, tmp_path: Path):
    rules = tmp_path / "rules.toml"
    rules.write_text("title='x'", encoding="utf-8")
    monkeypatch.setattr(github_dork, "GITLEAKS_RULES", rules)
    monkeypatch.setattr(github_dork.shutil, "which", lambda _name: "gitleaks")

    def fake_run(cmd, **kwargs):
        report = Path(cmd[cmd.index("--report-path") + 1])
        report.write_text(json.dumps([{"RuleID": "proxy-uri"}]), encoding="utf-8")
        return SimpleNamespace(returncode=1, stdout="human log", stderr="")

    monkeypatch.setattr(github_dork.subprocess, "run", fake_run)
    assert github_dork._run_gitleaks_dir(tmp_path) == [{"RuleID": "proxy-uri"}]


def test_tg_triage_does_not_claim_unperformed_checks():
    uri = "vless://00000000-0000-0000-0000-000000000001@example.net:443"
    result = tg_recon.honeytrap_triage(
        uri, "channel", [{"uri": uri, "channel": "channel"}]
    )
    assert result["verdict"] == "inconclusive"
    assert result["complete"] is False
    assert "ttl" in result["unassessed_checks"]
    assert not any(reason.startswith("ttl:") for reason in result["reasons"])
