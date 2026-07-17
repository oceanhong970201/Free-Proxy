from __future__ import annotations

import hashlib
import http.client
import json
import socket
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from aggregator.models import ProxyNode
import dashboard.ip_checker as ip_checker_module
from dashboard.ip_checker import (
    IpCheckJobManager,
    NodeIpChecker,
    _consensus_purity,
    _normalize_reputation,
    _parse_provider_body,
    resolve_public_endpoint,
)
from dashboard.server import create_server
from dashboard.service import (
    DashboardConfig,
    DashboardService,
    load_dashboard_config,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_STATUS_URL = (
    "https://raw.githubusercontent.com/oceanhong970201/Free-Proxy/"
    "master/output/pipeline-status.json"
)


def _sample_root(tmp_path: Path) -> tuple[Path, str, str]:
    (tmp_path / "state").mkdir()
    (tmp_path / "output").mkdir()
    (tmp_path / "config").mkdir()
    raw = "ss://RAW-CREDENTIAL-MATERIAL"
    password = "dashboard-secret-password"
    node = ProxyNode(
        proto="ss",
        host="8.8.8.8",
        port=8443,
        password=password,
        method="aes-128-gcm",
        raw=raw,
        name=f"malicious {raw} {password}",
        source="source-a",
    )
    with closing(sqlite3.connect(tmp_path / "nodes.db")) as conn, conn:
        conn.executescript(
            (PROJECT_ROOT / "infra" / "d1" / "schema.sql").read_text(
                encoding="utf-8"
            )
        )
        conn.execute(
            """INSERT INTO nodes(
                   uri,proto,host,port,password,method,source,alive,node_json
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                raw,
                node.proto,
                node.host,
                node.port,
                password,
                node.method,
                node.source,
                None,
                node.model_dump_json(),
            ),
        )
        conn.commit()
    (tmp_path / "state" / "sources.json").write_text(
        json.dumps(
            [
                {
                    "id": "source-a",
                    "url": "https://user:source-token@example.test/sub?token=secret",
                    "enabled": False,
                    "tier": 3,
                    "format": "clash",
                    "status": "disabled_canary",
                    "note": "secret-note",
                }
            ]
        ),
        encoding="utf-8",
    )
    return tmp_path, raw, password


def _service(root: Path) -> DashboardService:
    return DashboardService(root, DashboardConfig(worker_url=""))


def test_dashboard_config_clamps_purity_runtime_limits(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    path = tmp_path / "config" / "dashboard.yaml"
    path.write_text(
        """
pipeline_status_timeout_seconds: 0
pipeline_status_cache_seconds: -1
pipeline_status_stale_seconds: 0
ip_checker:
  purity_timeout_seconds: -10
  purity_cache_seconds: -1
  purity_provider_concurrency: 0
""".strip(),
        encoding="utf-8",
    )

    minimums = load_dashboard_config(tmp_path)
    assert minimums.pipeline_status_timeout_seconds == 1.0
    assert minimums.pipeline_status_cache_seconds == 5
    assert minimums.pipeline_status_stale_seconds == 60
    assert minimums.purity_timeout_seconds == 1.0
    assert minimums.purity_cache_seconds == 0
    assert minimums.purity_provider_concurrency == 1

    path.write_text(
        """
pipeline_status_timeout_seconds: 999
pipeline_status_cache_seconds: 999999999
pipeline_status_stale_seconds: 999999999
ip_checker:
  purity_timeout_seconds: 999
  purity_cache_seconds: 999999999
  purity_provider_concurrency: 99
""".strip(),
        encoding="utf-8",
    )

    maximums = load_dashboard_config(tmp_path)
    assert maximums.pipeline_status_timeout_seconds == 15.0
    assert maximums.pipeline_status_cache_seconds == 3_600
    assert maximums.pipeline_status_stale_seconds == 604_800
    assert maximums.purity_timeout_seconds == 30.0
    assert maximums.purity_cache_seconds == 604_800
    assert maximums.purity_provider_concurrency == 3


def _pipeline_document(
    generated_at: float,
    *,
    pipeline_status: str = "healthy",
) -> dict[str, Any]:
    healthy = pipeline_status == "healthy"
    return {
        "schema_version": 1,
        "generated_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(generated_at)
        ),
        "pipeline_status": pipeline_status,
        "verify": {
            "total": 4,
            "verified": 4 if healthy else 3,
            "alive": 3,
            "dead": 1 if healthy else 0,
            "unverified": 0 if healthy else 1,
            "tier1_alive": 3 if healthy else 2,
            "tier2_passed": 2,
            "completed": healthy,
        },
        "artifacts": {
            "node_count": 3,
            "clash_proxies": 3,
            "singbox_outbounds": 2,
            "rss_items": 3,
        },
    }


def _service_with_remote_pipeline(
    root: Path,
    *,
    stale_seconds: int = 3600,
) -> DashboardService:
    return DashboardService(
        root,
        DashboardConfig(
            worker_url="",
            pipeline_status_url=PIPELINE_STATUS_URL,
            pipeline_status_cache_seconds=60,
            pipeline_status_stale_seconds=stale_seconds,
        ),
    )


def test_remote_pipeline_good_schema_is_allowlisted_and_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, raw, password = _sample_root(tmp_path)
    service = _service_with_remote_pipeline(root)
    calls = 0
    document = _pipeline_document(time.time())
    document["verify"] = {**document["verify"]}

    def download(_url: str) -> object:
        nonlocal calls
        calls += 1
        return document

    monkeypatch.setattr(service, "_download_pipeline_status", download)
    first = service.status()["remote_pipeline"]
    second = service.status()["remote_pipeline"]

    assert calls == 1
    assert {**first, "age_seconds": None} == {
        **second,
        "age_seconds": None,
    }
    assert second["age_seconds"] >= first["age_seconds"]
    assert first["configured"] is True
    assert first["status"] == "healthy"
    assert first["pipeline_status"] == "healthy"
    assert first["stale"] is False
    assert first["verify"]["completed"] is True
    assert first["artifacts"]["node_count"] == 3
    serialized = json.dumps(first, ensure_ascii=False)
    assert PIPELINE_STATUS_URL not in serialized
    assert raw not in serialized
    assert password not in serialized


def test_remote_pipeline_stale_and_bootstrap_unknown_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    service = _service_with_remote_pipeline(root, stale_seconds=60)
    monkeypatch.setattr(
        service,
        "_download_pipeline_status",
        lambda _url: _pipeline_document(time.time() - 120),
    )
    stale = service.status()["remote_pipeline"]
    assert stale["status"] == "stale"
    assert stale["pipeline_status"] == "healthy"
    assert stale["stale"] is True
    assert stale["age_seconds"] >= 119

    bootstrap = _service_with_remote_pipeline(root)
    monkeypatch.setattr(
        bootstrap,
        "_download_pipeline_status",
        lambda _url: _pipeline_document(time.time(), pipeline_status="unknown"),
    )
    unknown = bootstrap.status()["remote_pipeline"]
    assert unknown["status"] == "unknown"
    assert unknown["stale"] is False
    assert unknown["verify"]["completed"] is False


def _empty_unknown_pipeline_document(generated_at: float) -> dict[str, Any]:
    document = _pipeline_document(generated_at, pipeline_status="unknown")
    document["verify"] = {
        "total": 0,
        "verified": 0,
        "alive": 0,
        "dead": 0,
        "unverified": 0,
        "tier1_alive": 0,
        "tier2_passed": 0,
        "completed": False,
    }
    document["artifacts"] = {
        "node_count": 0,
        "clash_proxies": 0,
        "singbox_outbounds": 0,
        "rss_items": 0,
    }
    return document


def test_remote_pipeline_unknown_accepts_zero_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    service = _service_with_remote_pipeline(root)
    monkeypatch.setattr(
        service,
        "_download_pipeline_status",
        lambda _url: _empty_unknown_pipeline_document(time.time()),
    )

    remote = service.status()["remote_pipeline"]

    assert remote["status"] == "unknown"
    assert remote["stale"] is False
    assert remote["verify"]["total"] == 0
    assert remote["artifacts"]["node_count"] == 0
    assert "error" not in remote


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("clash_proxies", 1),
        ("rss_items", 1),
        ("singbox_outbounds", 1),
    ],
)
def test_remote_pipeline_unknown_rejects_inconsistent_artifact_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    service = _service_with_remote_pipeline(root)
    document = _empty_unknown_pipeline_document(time.time())
    document["artifacts"][field] = value
    monkeypatch.setattr(
        service,
        "_download_pipeline_status",
        lambda _url: document,
    )

    remote = service.status()["remote_pipeline"]

    assert remote["status"] == "unknown"
    assert remote["stale"] is True
    assert remote["verify"] is None
    assert remote["error"] == "invalid_schema"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.update({"unexpected": "provider-raw-secret"}),
        lambda document: document["verify"].update({"total": True}),
        lambda document: document["verify"].update({"verified": 3}),
        lambda document: document["artifacts"].update(
            {"raw": "provider-raw-secret"}
        ),
    ],
)
def test_remote_pipeline_rejects_malformed_or_extended_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Any,
) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    service = _service_with_remote_pipeline(root)
    document = _pipeline_document(time.time())
    mutate(document)
    monkeypatch.setattr(
        service,
        "_download_pipeline_status",
        lambda _url: document,
    )

    remote = service.status()["remote_pipeline"]

    assert remote["status"] == "unknown"
    assert remote["stale"] is True
    assert remote["verify"] is None
    assert remote["error"] == "invalid_schema"
    assert "provider-raw-secret" not in json.dumps(remote)


def test_remote_pipeline_network_failure_is_unknown_then_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    service = _service_with_remote_pipeline(root)

    def network_failure(_url: str) -> object:
        raise OSError("https://user:token@private.invalid/provider-raw-secret")

    monkeypatch.setattr(service, "_download_pipeline_status", network_failure)
    unavailable = service.status()["remote_pipeline"]
    assert unavailable["status"] == "unknown"
    assert unavailable["error"] == "network_error"
    assert "token" not in json.dumps(unavailable)

    monkeypatch.setattr(
        service,
        "_download_pipeline_status",
        lambda _url: _pipeline_document(time.time()),
    )
    healthy = service.status(force_remote=True)["remote_pipeline"]
    assert healthy["status"] == "healthy"

    monkeypatch.setattr(service, "_download_pipeline_status", network_failure)
    fallback = service.status(force_remote=True)["remote_pipeline"]
    assert fallback["status"] == "stale"
    assert fallback["pipeline_status"] == "healthy"
    assert fallback["verify"] == healthy["verify"]
    assert fallback["error"] == "network_error"


def test_frontend_only_labels_an_existing_remote_snapshot_as_stale() -> None:
    script = (PROJECT_ROOT / "src" / "dashboard" / "static" / "app.js").read_text(
        encoding="utf-8"
    )

    assert "function hasRemoteSnapshot(remote)" in script
    assert (
        'stale === true && hasRemoteSnapshot(remote) ? "stale" : "unknown"'
        in script
    )
    assert (
        'const freshness = !remoteHasSnapshot ? "尚無有效快照"'
        in script
    )
    assert 'else if (!remoteHasSnapshot) setStateNote(' in script
    assert 'else if (remoteStatus !== "healthy") setStateNote(' in script


def test_frontend_does_not_render_missing_remote_age_as_zero_seconds() -> None:
    script = (PROJECT_ROOT / "src" / "dashboard" / "static" / "app.js").read_text(
        encoding="utf-8"
    )

    assert (
        'if (value === null || value === undefined || value === "") return "—";\n'
        "  const seconds = Number(value);"
        in script
    )


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://127.0.0.1/output/pipeline-status.json",
        "https://localhost/output/pipeline-status.json",
        (
            "https://user:token@raw.githubusercontent.com/owner/repo/"
            "master/output/pipeline-status.json"
        ),
        (
            "https://raw.githubusercontent.com/owner/repo/master/"
            "output/pipeline-status.json?token=secret"
        ),
        (
            "https://raw.githubusercontent.com/owner/repo/master/"
            "output/pipeline-status.json"
        ),
        (
            "https://raw.githubusercontent.com/oceanhong970201/Free-Proxy/dev/"
            "output/pipeline-status.json"
        ),
        (
            "https://raw.githubusercontent.com/oceanhong970201/Free-Proxy/"
            "master/state/pipeline-status.json"
        ),
    ],
)
def test_pipeline_status_config_rejects_ssrf_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_url: str,
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "dashboard.yaml").write_text(
        f"pipeline_status_url: {unsafe_url}\n",
        encoding="utf-8",
    )
    assert load_dashboard_config(tmp_path).pipeline_status_url == ""

    service = DashboardService(
        tmp_path,
        DashboardConfig(worker_url="", pipeline_status_url=unsafe_url),
    )
    calls = 0

    def should_not_fetch(_url: str) -> object:
        nonlocal calls
        calls += 1
        return _pipeline_document(time.time())

    monkeypatch.setattr(service, "_download_pipeline_status", should_not_fetch)
    remote = service.status()["remote_pipeline"]
    assert calls == 0
    assert remote["configured"] is False
    assert remote["status"] == "unknown"
    assert remote["error"] == "invalid_config"
    serialized = json.dumps(remote)
    assert unsafe_url not in serialized
    assert "token" not in serialized


def test_service_redacts_credentials_and_persists_sanitized_result(
    tmp_path: Path,
) -> None:
    root, raw, password = _sample_root(tmp_path)
    service = _service(root)

    payload = service.nodes()
    assert payload["total"] == 1
    item = payload["items"][0]
    serialized = json.dumps(payload, ensure_ascii=False)
    assert raw not in serialized
    assert password not in serialized
    assert "malicious" not in item["name"]
    assert "raw" not in item
    assert "password" not in item
    assert service.node_for_check(item["id"]).password == password

    service.persist_ip_result(
        {
            "node_id": item["id"],
            "mode": "exit",
            "status": "passed",
            "checked_at": int(time.time()),
            "duration_ms": 25.2,
            "endpoint_ips": ["8.8.8.8", "127.0.0.1"],
            "exit_ips": ["1.1.1.1"],
            "exit_ip": "1.1.1.1",
            "raw": raw,
            "password": password,
            "providers": [{"provider": "edge-trace", "ip": "1.1.1.1"}],
        }
    )
    persisted = (root / "state" / "ip-check-results.jsonl").read_text(
        encoding="utf-8"
    )
    assert raw not in persisted
    assert password not in persisted
    assert "127.0.0.1" not in persisted
    assert service.nodes()["items"][0]["ip_check"]["exit_ip"] == "1.1.1.1"

    sources = service.sources()
    assert sources[0]["origin"] == "example.test"
    assert "url" not in sources[0]
    assert "note" not in sources[0]
    assert "source-token" not in json.dumps(sources)


def test_ip_check_and_purity_results_survive_per_mode_reload(tmp_path: Path) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    service = _service(root)
    node_id = service.nodes()["items"][0]["id"]
    service.persist_ip_result(
        {
            "node_id": node_id,
            "mode": "exit",
            "status": "passed",
            "checked_at": 100,
            "duration_ms": 5,
            "cached": False,
            "endpoint_ips": ["8.8.8.8"],
            "exit_ips": ["9.9.9.9"],
            "exit_ip": "9.9.9.9",
        }
    )
    service.persist_ip_result(
        {
            "node_id": node_id,
            "mode": "purity",
            "status": "passed",
            "checked_at": 200,
            "duration_ms": 10,
            "cached": False,
            "endpoint_ips": ["8.8.8.8"],
            "exit_ips": ["9.9.9.9"],
            "exit_ip": "9.9.9.9",
            "purity_score": 92,
            "purity_grade": "A",
            "purity_reasons": [],
            "purity_confidence": "high",
            "provider_coverage": {"ok": 3, "total": 3},
        }
    )

    # A fresh service forces a disk reload rather than relying on the writer's
    # in-memory cache. Purity must not displace endpoint/exit observations.
    item = _service(root).nodes()["items"][0]
    assert item["ip_check"]["mode"] == "exit"
    assert item["ip_check"]["exit_ip"] == "9.9.9.9"
    assert item["ip_purity"]["mode"] == "purity"
    assert item["ip_purity"]["purity_score"] == 92
    assert item["ip_purity"]["purity_confidence"] == "high"


def test_status_does_not_echo_parser_or_pipeline_secret(tmp_path: Path) -> None:
    root, _raw, password = _sample_root(tmp_path)
    (root / "output" / "clash.yaml").write_text(
        f'proxies: ["unterminated\\q{password}"]', encoding="utf-8"
    )
    (root / "state" / "last-run.json").write_text(
        json.dumps(
            {
                "ts": int(time.time()),
                "last_stage_cmd": "publish",
                "counts": {
                    "publish": {"success": False, "error": f"failed {password}"}
                },
            }
        ),
        encoding="utf-8",
    )
    payload = _service(root).status()
    serialized = json.dumps(payload, ensure_ascii=False)
    assert password not in serialized
    assert payload["pipeline_status"] == "attention"
    assert payload["latest_run"]["status"] == "failed"
    assert payload["latest_pipeline"]["summary"]["error"] == "stage_failed"


def test_local_verification_with_zero_verified_nodes_remains_unknown(
    tmp_path: Path,
) -> None:
    root, _raw, _password = _sample_root(tmp_path)

    payload = _service(root).status()

    assert payload["local_verification"] == {
        "status": "unknown",
        "total": 1,
        "verified": 0,
        "alive": 0,
        "dead": 0,
        "unverified": 1,
        "tier1_alive": 0,
        "tier2_passed": 0,
        "completed": False,
        "updated_at": None,
        "age_seconds": None,
    }
    # Existing status keys remain available to older dashboard clients.
    assert payload["pipeline_status"] == "attention"
    assert payload["latest_pipeline"] == payload["latest_run"]


def test_ip_parsers_reject_non_public_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(ValueError, match="non-public"):
        resolve_public_endpoint("node.invalid", 443)
    with pytest.raises(ValueError, match="non-public"):
        _parse_provider_body("json", '{"ip":"10.0.0.1"}')
    with pytest.raises(ValueError, match="non-public"):
        _parse_provider_body("json", '{"ip":"224.0.0.1"}')


@pytest.mark.parametrize(
    ("provider", "kind", "document", "expected_risk", "expected_signals"),
    [
        (
            "network-risk",
            "generic",
            {
                "ip": "8.8.8.8",
                "risk": {
                    "is_vpn": True,
                    "is_tor": False,
                    "is_proxy": False,
                    "is_datacenter": True,
                    "risk_score": 63,
                },
            },
            63,
            ["datacenter", "vpn"],
        ),
        (
            "network-profile",
            "generic",
            {
                "ip": "8.8.8.8",
                "is_proxy": False,
                "is_vpn": False,
                "is_tor": False,
                "is_datacenter": False,
                "is_abuser": False,
                "company": {"name": "must-not-be-returned"},
            },
            0,
            [],
        ),
        (
            "proxy-risk",
            "keyed",
            {
                "status": "ok",
                "8.8.8.8": {
                    "proxy": "yes",
                    "type": "VPN",
                    "risk": "66",
                    "operator": "must-not-be-returned",
                },
            },
            66,
            ["known_proxy", "vpn"],
        ),
    ],
)
def test_reputation_provider_parsers_normalize_three_fixed_schemas(
    provider: str,
    kind: str,
    document: dict[str, Any],
    expected_risk: int,
    expected_signals: list[str],
) -> None:
    result = _normalize_reputation(provider, kind, document, "8.8.8.8")

    assert result == {
        "provider": provider,
        "status": "ok",
        "risk_score": expected_risk,
        "signals": expected_signals,
        "cached": False,
    }


def _provider_result(
    provider: str, risk_score: int, *signals: str
) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": "ok",
        "risk_score": risk_score,
        "signals": list(signals),
        "cached": False,
    }


@pytest.mark.parametrize(
    ("risk", "expected_score", "expected_grade"),
    [
        (0, 100, "A"),
        (10, 90, "A"),
        (11, 89, "B"),
        (25, 75, "B"),
        (26, 74, "C"),
        (40, 60, "C"),
        (41, 59, "D"),
        (60, 40, "D"),
        (61, 39, "F"),
    ],
)
def test_purity_scoring_grade_boundaries(
    risk: int, expected_score: int, expected_grade: str
) -> None:
    providers = [
        _provider_result(name, risk)
        for name in ("network-risk", "network-profile", "proxy-risk")
    ]

    score, grade, reasons = _consensus_purity(providers)

    assert (score, grade) == (expected_score, expected_grade)
    if risk >= 50:
        assert "elevated_risk" in reasons


def test_purity_scoring_clean_disagreement_and_high_risk() -> None:
    clean = [
        _provider_result(name, 0)
        for name in ("network-risk", "network-profile", "proxy-risk")
    ]
    assert _consensus_purity(clean) == (100, "A", [])

    disagreement = [
        _provider_result("network-risk", 0),
        _provider_result("network-profile", 25),
        _provider_result("proxy-risk", 25),
    ]
    score, grade, reasons = _consensus_purity(disagreement)
    assert (score, grade) == (74, "C")
    assert "provider_disagreement" in reasons

    high_risk = [
        _provider_result(name, 100, "tor")
        for name in ("network-risk", "network-profile", "proxy-risk")
    ]
    assert _consensus_purity(high_risk) == (0, "F", ["tor"])


def _purity_checker(tmp_path: Path) -> tuple[NodeIpChecker, str]:
    node_id = "a" * 64
    node = ProxyNode(
        proto="ss",
        host="node.example.test",
        port=443,
        password="local-test-secret",
        method="aes-128-gcm",
        raw="ss://local-test-secret",
        source="test",
    )
    checker = NodeIpChecker(
        root=tmp_path,
        node_loader=lambda requested: node if requested == node_id else None,
        timeout_seconds=5,
        cache_seconds=0,
    )
    # These are capability sentinels only. Tests replace the process/network
    # boundary below, so no binary or external service is invoked.
    checker.mihomo = "test-mihomo"
    checker.curl = "test-curl"
    return checker, node_id


def _successful_exit(node_id: str, mode: str = "purity") -> dict[str, Any]:
    return {
        "node_id": node_id,
        "mode": mode,
        "status": "passed",
        "endpoint_ips": ["8.8.8.8"],
        "exit_ips": ["9.9.9.9"],
        "exit_ip": "9.9.9.9",
        "direct_match": False,
        "providers": [],
        "checked_at": int(time.time()),
        "duration_ms": 1.0,
        "cached": False,
    }


def test_purity_check_runs_exit_discovery_before_reputation_providers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checker, node_id = _purity_checker(tmp_path)
    events: list[str] = []
    monkeypatch.setattr(
        ip_checker_module,
        "resolve_public_endpoint",
        lambda _host, _port: ["8.8.8.8"],
    )
    monkeypatch.setattr(ip_checker_module, "_tcp_probe", lambda _host, _port: 1.0)

    def fake_exit(
        requested_id: str,
        _node: ProxyNode,
        _addresses: list[str],
        _latency: float,
        _cancel: threading.Event,
        _started: float,
        _deadline: float,
        result_mode: str,
    ) -> dict[str, Any]:
        events.append("exit")
        return _successful_exit(requested_id, result_mode)

    def fake_reputation(
        provider: str,
        _template: str,
        _kind: str,
        _exit_ip: str,
        _cancel: threading.Event,
        _deadline: float,
    ) -> dict[str, Any]:
        events.append(provider)
        return _provider_result(provider, 0)

    monkeypatch.setattr(checker, "_exit_check", fake_exit)
    monkeypatch.setattr(checker, "_fetch_reputation", fake_reputation)
    try:
        result = checker.check(node_id, "purity")
    finally:
        checker.close()

    assert result["status"] == "passed"
    assert result["purity_score"] == 100
    assert events == [
        "exit",
        "network-risk",
        "network-profile",
        "proxy-risk",
    ]


@pytest.mark.parametrize("exit_status", ["failed", "cancelled"])
def test_exit_failure_or_cancellation_skips_all_reputation_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_status: str,
) -> None:
    checker, node_id = _purity_checker(tmp_path)
    monkeypatch.setattr(
        ip_checker_module,
        "resolve_public_endpoint",
        lambda _host, _port: ["8.8.8.8"],
    )
    monkeypatch.setattr(ip_checker_module, "_tcp_probe", lambda _host, _port: 1.0)
    provider_calls = 0

    def fake_exit(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        result = {
            "node_id": node_id,
            "mode": "purity",
            "status": exit_status,
            "checked_at": int(time.time()),
            "cached": False,
        }
        if exit_status == "failed":
            result["error"] = "all_ip_probes_failed"
        return result

    def fail_if_called(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("reputation provider called without a usable exit IP")

    monkeypatch.setattr(checker, "_exit_check", fake_exit)
    monkeypatch.setattr(checker, "_fetch_reputation", fail_if_called)
    try:
        result = checker.check(node_id, "purity")
    finally:
        checker.close()

    assert result["status"] == exit_status
    assert provider_calls == 0


@pytest.mark.parametrize(
    ("successful_providers", "expected_status", "expected_error"),
    [
        (1, "partial", None),
        (0, "failed", "all_reputation_probes_failed"),
    ],
)
def test_purity_handles_partial_and_total_provider_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    successful_providers: int,
    expected_status: str,
    expected_error: str | None,
) -> None:
    checker, node_id = _purity_checker(tmp_path)
    provider_calls: list[str] = []

    def fake_reputation(
        provider: str,
        _template: str,
        _kind: str,
        _exit_ip: str,
        _cancel: threading.Event,
        _deadline: float,
    ) -> dict[str, Any]:
        provider_calls.append(provider)
        if len(provider_calls) <= successful_providers:
            return _provider_result(provider, 10)
        return {
            "provider": provider,
            "status": "error",
            "error": "provider_timeout",
        }

    monkeypatch.setattr(checker, "_fetch_reputation", fake_reputation)
    try:
        result = checker._purity_check(
            _successful_exit(node_id),
            cancel_event=threading.Event(),
            started=time.perf_counter(),
            deadline=time.monotonic() + 5,
        )
    finally:
        checker.close()

    assert result["status"] == expected_status
    assert result["provider_coverage"] == {
        "ok": successful_providers,
        "total": 3,
    }
    assert provider_calls == ["network-risk", "network-profile", "proxy-risk"]
    if expected_error is None:
        assert result["purity_score"] == 90
        assert "limited_provider_coverage" in result["purity_reasons"]
    else:
        assert result["error"] == expected_error
        assert "purity_score" not in result


def test_purity_sanitizer_drops_secrets_nan_and_unknown_signals() -> None:
    secret = "credential-bearing-provider-payload"
    clean = DashboardService._sanitize_ip_result(
        {
            "node_id": "a" * 64,
            "mode": "purity",
            "status": "passed",
            "checked_at": 123,
            "duration_ms": 10,
            "cached": False,
            "exit_ip": "9.9.9.9",
            "exit_ips": ["9.9.9.9", "224.0.0.1"],
            "purity_score": float("nan"),
            "purity_grade": "A",
            "purity_reasons": ["vpn", "unknown_signal", secret],
            "purity_confidence": "unknown",
            "reputation_providers": [
                {
                    "provider": "network-risk",
                    "status": "ok",
                    "risk_score": float("nan"),
                    "signals": ["vpn", "unknown_signal", secret],
                    "cached": False,
                    "raw": secret,
                    "token": secret,
                },
                {
                    "provider": "unapproved-provider",
                    "status": "ok",
                    "risk_score": 0,
                    "signals": [],
                    "raw": secret,
                },
            ],
            "provider_coverage": {"ok": 1, "total": 3},
            "raw": secret,
            "token": secret,
        }
    )

    assert clean is not None
    assert clean["exit_ips"] == ["9.9.9.9"]
    assert "purity_score" not in clean
    assert "purity_grade" not in clean
    assert "purity_confidence" not in clean
    assert clean["purity_reasons"] == ["vpn"]
    assert clean["reputation_providers"] == [
        {
            "provider": "network-risk",
            "status": "ok",
            "cached": False,
            "signals": ["vpn"],
        }
    ]
    serialized = json.dumps(clean, allow_nan=False)
    assert secret not in serialized
    assert "unknown_signal" not in serialized
    assert DashboardService._sanitize_ip_result(
        {
            "node_id": "a" * 64,
            "mode": "purity",
            "status": "passed",
            "checked_at": 123,
            "duration_ms": float("nan"),
        }
    ) is None


def _wait_job(manager: IpCheckJobManager, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        snapshot = manager.snapshot(job_id)
        assert snapshot is not None
        if snapshot["status"] in {"completed", "cancelled"}:
            return snapshot
        time.sleep(0.01)
    raise AssertionError("IP-check job did not complete")


def test_job_manager_counts_results_and_contains_worker_exceptions() -> None:
    class Checker:
        def check(self, node_id: str, mode: str, _cancel: threading.Event) -> dict[str, Any]:
            if node_id.startswith("b"):
                raise RuntimeError("credential-bearing diagnostic")
            return {
                "node_id": node_id,
                "mode": mode,
                "status": "passed",
                "checked_at": int(time.time()),
                "cached": False,
            }

    persisted: list[dict[str, Any]] = []
    manager = IpCheckJobManager(Checker(), max_workers=2, persist=persisted.append)  # type: ignore[arg-type]
    try:
        created = manager.create(["a" * 64, "b" * 64], "endpoint")
        result = _wait_job(manager, created["id"])
        assert result["completed"] == 2
        assert result["counts"] == {"passed": 1, "failed": 1}
        assert len(persisted) == 2
        assert all("credential-bearing" not in json.dumps(item) for item in persisted)
    finally:
        manager.close()


def _request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_loopback_server_static_security_and_job_persistence(tmp_path: Path) -> None:
    root, raw, password = _sample_root(tmp_path)
    server = create_server(root, port=0)
    port = int(server.server_address[1])

    def fake_check(
        node_id: str, mode: str, _cancel: threading.Event
    ) -> dict[str, Any]:
        return {
            "node_id": node_id,
            "mode": mode,
            "status": "passed",
            "endpoint_ips": ["8.8.8.8"],
            "tcp_latency_ms": 12.5,
            "checked_at": int(time.time()),
            "cached": False,
        }

    server.node_checker.check = fake_check  # type: ignore[method-assign]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, html = _request(port, "GET", "/")
        assert status == 200
        assert b"Proxy Operations Console" in html
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert _request(port, "GET", "/app.js")[0] == 200

        status, _headers, body = _request(port, "GET", "/api/nodes?limit=1")
        assert status == 200
        nodes = json.loads(body)
        node_id = nodes["items"][0]["id"]
        assert raw.encode() not in body
        assert password.encode() not in body

        status, _headers, body = _request(port, "GET", "/api/status?force=true")
        assert status == 403
        status, _headers, _body = _request(
            port,
            "GET",
            "/api/status?force=true",
            headers={"X-Dashboard-Action": "refresh"},
        )
        assert status == 200

        request_body = json.dumps(
            {"node_ids": [node_id], "mode": "endpoint"}
        ).encode()
        status, _headers, body = _request(
            port,
            "POST",
            "/api/ip-checks",
            body=request_body,
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
            },
        )
        assert status == 202
        job_id = json.loads(body)["id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status, _headers, body = _request(port, "GET", f"/api/ip-checks/{job_id}")
            job = json.loads(body)
            if job["status"] == "completed":
                break
            time.sleep(0.02)
        assert status == 200
        assert job["completed"] == 1

        status, _headers, body = _request(port, "GET", "/api/nodes?limit=1")
        assert status == 200
        assert json.loads(body)["items"][0]["ip_check"]["status"] == "passed"

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.putrequest("GET", "/api/status", skip_host=True)
        connection.putheader("Host", "example.invalid")
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 421
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    restarted = _service(root).nodes(limit=1)
    assert restarted["items"][0]["ip_check"]["status"] == "passed"


def test_server_accepts_purity_job_and_fails_closed_without_capability(
    tmp_path: Path,
) -> None:
    root, _raw, _password = _sample_root(tmp_path)
    server = create_server(root, port=0)
    port = int(server.server_address[1])
    node_id = server.dashboard_service.nodes(limit=1)["items"][0]["id"]
    purity_available = True

    def capabilities() -> dict[str, Any]:
        return {
            "endpoint": True,
            "exit_ip": True,
            "purity": purity_available,
            "purity_providers": [
                "network-risk",
                "network-profile",
                "proxy-risk",
            ],
        }

    def fake_check(
        requested_id: str, mode: str, _cancel: threading.Event
    ) -> dict[str, Any]:
        return {
            **_successful_exit(requested_id, mode),
            "purity_score": 100,
            "purity_grade": "A",
            "purity_reasons": [],
            "purity_confidence": "high",
            "provider_coverage": {"ok": 3, "total": 3},
        }

    server.node_checker.capabilities = capabilities  # type: ignore[method-assign]
    server.node_checker.check = fake_check  # type: ignore[method-assign]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    headers = {
        "Content-Type": "application/json",
        "Origin": f"http://127.0.0.1:{port}",
    }
    request_body = json.dumps(
        {"node_ids": [node_id], "mode": "purity"}
    ).encode()
    try:
        status, _headers, body = _request(
            port,
            "POST",
            "/api/ip-checks",
            body=request_body,
            headers=headers,
        )
        assert status == 202
        accepted = json.loads(body)
        assert accepted["mode"] == "purity"
        assert accepted["total"] == 1

        purity_available = False
        status, _headers, body = _request(
            port,
            "POST",
            "/api/ip-checks",
            body=request_body,
            headers=headers,
        )
        assert status == 503
        assert json.loads(body) == {"error": "checker_runtime_unavailable"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_server_rejects_non_loopback_bind(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="loopback"):
        create_server(tmp_path, host="0.0.0.0", port=0)


def test_opaque_id_is_sha256_of_server_side_uri(tmp_path: Path) -> None:
    root, raw, _password = _sample_root(tmp_path)
    item = _service(root).nodes()["items"][0]
    assert item["id"] == hashlib.sha256(raw.encode()).hexdigest()
    assert len(item["id"]) == 64
