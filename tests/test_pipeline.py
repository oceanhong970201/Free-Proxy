from __future__ import annotations

import asyncio
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import yaml
import pytest

from aggregator import cli, emit, fetcher, tcp_prefilter, vpnsuper_feed
from aggregator.models import ProxyNode


@pytest.fixture(autouse=True)
def _isolate_cli_last_run(monkeypatch, tmp_path: Path) -> None:
    """Keep every pipeline test from writing the workspace runtime status."""
    monkeypatch.setattr(cli, "LAST_RUN", tmp_path / "last-run.json")


def _configure_temp_pipeline(monkeypatch, tmp_path: Path) -> list[dict]:
    root = tmp_path
    state = root / "state"
    state.mkdir(parents=True)
    schema_dir = root / "infra" / "d1"
    schema_dir.mkdir(parents=True)
    source_schema = Path(__file__).resolve().parents[1] / "infra" / "d1" / "schema.sql"
    (schema_dir / "schema.sql").write_text(
        source_schema.read_text(encoding="utf-8"), encoding="utf-8"
    )

    monkeypatch.setattr(cli, "ROOT", root)
    monkeypatch.setattr(cli, "STATE", state)
    monkeypatch.setattr(cli, "DB", root / "nodes.db")
    monkeypatch.setattr(cli, "STAGING", state / "staging.jsonl")
    monkeypatch.setattr(cli, "LIVE", state / "live.jsonl")
    monkeypatch.setattr(cli, "LAST_RUN", state / "last-run.json")

    sources = [
        {
            "id": "fixture",
            "url": "https://example.invalid/sub",
            "format": "raw",
            "enabled": True,
            "tier": 1,
            "status": "ok",
        }
    ]
    monkeypatch.setattr(cli, "_read_sources", lambda: sources)
    monkeypatch.setattr(fetcher, "save_sources", lambda _sources: None)
    return sources


def _write_same_endpoint_nodes() -> str:
    return "\n".join(
        [
            "vless://00000000-0000-0000-0000-000000000001@edge.example:443"
            "?security=tls&type=ws&path=%2Fa&host=a.example#first",
            "vless://00000000-0000-0000-0000-000000000002@edge.example:443"
            "?security=tls&type=ws&path=%2Fb&host=b.example#second",
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@ss.example:8388#ss",
        ]
    )


def test_speedtest_binary_override_is_portable(monkeypatch, tmp_path):
    binary = tmp_path / (
        "clash-speedtest.exe" if cli.os.name == "nt" else "clash-speedtest"
    )
    binary.write_bytes(b"fixture")
    monkeypatch.setenv("CLASH_SPEEDTEST_BIN", str(binary))
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)

    assert cli._find_speedtest_binary() == str(binary)


def test_parse_persists_complete_node_json(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )

    summary = cli._parse_logic()

    assert summary["success"] is True
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        rows = conn.execute(
            "SELECT uri, method, path, host_header, node_json FROM nodes"
        ).fetchall()
    assert len(rows) == 3
    documents = [json.loads(row[4]) for row in rows]
    assert {doc.get("path") for doc in documents} >= {"/a", "/b"}
    assert {doc.get("host_header") for doc in documents} >= {"a.example", "b.example"}
    assert any(doc.get("method") == "aes-128-gcm" for doc in documents)


def test_verify_keeps_same_endpoint_credentials_independent(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True

    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {
            "max_latency_ms": 1000,
            "min_download_speed_mbps": 5,
            "tier1_concurrent": 10,
            "tier2_concurrent": 2,
            "download_size_bytes": 1024,
        },
    )
    monkeypatch.setattr(
        tcp_prefilter,
        "run",
        lambda proxies: {f"{proxy['server']}:{proxy['port']}" for proxy in proxies},
    )

    def fake_run(args, **_kwargs):
        config = Path(args[args.index("-c") + 1])
        proxies = yaml.safe_load(config.read_text(encoding="utf-8"))["proxies"]
        lines = []
        if "-fast" in args:
            for index, proxy in enumerate(proxies, 1):
                latency = "100ms" if proxy.get("uuid", "").endswith("1") else "N/A"
                lines.append(f"{index}.\t{proxy['name']}\t{proxy['type']}\t{latency}")
        else:
            for index, proxy in enumerate(proxies, 1):
                lines.append(
                    f"{index}.\t{proxy['name']}\t{proxy['type']}\t100ms\t0ms\t0%\t10MB/s"
                )
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    summary = cli._verify_logic()

    assert summary["success"] is True
    records = [
        json.loads(line) for line in cli.LIVE.read_text(encoding="utf-8").splitlines()
    ]
    by_uuid = {record.get("uuid"): record for record in records if record.get("uuid")}
    assert by_uuid["00000000-0000-0000-0000-000000000001"]["alive"] is True
    assert by_uuid["00000000-0000-0000-0000-000000000001"]["download_speed"] == 10
    assert by_uuid["00000000-0000-0000-0000-000000000002"]["alive"] is False
    assert by_uuid["00000000-0000-0000-0000-000000000002"]["download_speed"] is None


def test_publish_excludes_unverified_and_checks_snapshot_contract(
    monkeypatch, tmp_path
):
    live = tmp_path / "live.jsonl"
    verified = ProxyNode(
        proto="vless",
        host="edge.example",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
        raw=("vless://00000000-0000-0000-0000-000000000001@edge.example:443"),
        alive=True,
        latency_ms=100,
        download_speed=12,
    )
    unverified = verified.model_copy(
        update={
            "uuid": "00000000-0000-0000-0000-000000000002",
            "raw": ("vless://00000000-0000-0000-0000-000000000002@edge.example:443"),
            "alive": None,
        }
    )
    live.write_text(
        "\n".join(
            json.dumps(node.model_dump(mode="json")) for node in (verified, unverified)
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "LIVE", live)
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {"min_download_speed_mbps": 5, "top_n_publish": 100},
    )
    monkeypatch.setenv("ADMIN_TOKEN", "test-token")
    monkeypatch.setenv("WORKER_URL", "https://worker.example")

    captured = {}

    class Response:
        status_code = 200
        text = "ok"

        def raise_for_status(self):
            return None

        def json(self):
            payload = captured["json"]
            return {
                "ok": True,
                "complete": True,
                "snapshot_id": payload["snapshot_id"],
                "imported": payload["expected_count"],
                "expected": payload["expected_count"],
                "model_persisted": True,
            }

    def fake_post(_url, **kwargs):
        captured.update(kwargs)
        return Response()

    import httpx

    monkeypatch.setattr(httpx, "post", fake_post)
    summary = cli._publish_logic(strict=True)

    assert summary["success"] is True
    assert captured["json"]["expected_count"] == 1
    assert [node["uri"] for node in captured["json"]["nodes"]] == [verified.raw]
    assert captured["json"]["nodes"][0]["model"]["raw"] == verified.raw
    assert captured["json"]["nodes"][0]["model"]["uuid"] == verified.uuid


def test_publish_rejects_cleartext_non_loopback_worker_url(monkeypatch, tmp_path):
    live = tmp_path / "live.jsonl"
    node = ProxyNode(
        proto="vless",
        host="edge.example",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
        raw=("vless://00000000-0000-0000-0000-000000000001@edge.example:443"),
        alive=True,
        download_speed=10,
    )
    live.write_text(json.dumps(node.model_dump(mode="json")), encoding="utf-8")
    monkeypatch.setattr(cli, "LIVE", live)
    monkeypatch.setattr(cli, "_load_quality", lambda: {"min_download_speed_mbps": 5})
    monkeypatch.setenv("WORKER_URL", "http://worker.example")
    monkeypatch.setenv("ADMIN_TOKEN", "secret")

    import httpx

    def unexpected_post(*_args, **_kwargs):
        raise AssertionError("cleartext endpoint must be rejected before POST")

    monkeypatch.setattr(httpx, "post", unexpected_post)
    summary = cli._publish_logic(strict=True)

    assert summary["success"] is False
    assert "HTTPS" in summary["error"]


def test_incomplete_fetch_retains_previous_staging(monkeypatch, tmp_path):
    staging = tmp_path / "staging.jsonl"
    staging.write_text("previous snapshot", encoding="utf-8")
    sources = [
        {"id": "ok", "url": "https://one.invalid", "format": "raw", "enabled": True},
        {"id": "bad", "url": "https://two.invalid", "format": "raw", "enabled": True},
    ]
    monkeypatch.setattr(fetcher, "STAGING_FILE", staging)
    monkeypatch.setattr(fetcher, "load_sources", lambda: sources)
    monkeypatch.setattr(fetcher, "save_sources", lambda _sources: None)
    monkeypatch.setattr(fetcher, "_ua", lambda: "test")

    async def fake_fetch(_client, source):
        if source["id"] == "ok":
            return source, "vless://one@example:443", "ok"
        source["last_error"] = "timeout"
        return source, None, "error"

    monkeypatch.setattr(fetcher, "_fetch_one", fake_fetch)
    summary = asyncio.run(fetcher.fetch_all())

    assert summary["success"] is False
    assert summary["failed_sources"] == ["bad"]
    assert staging.read_text(encoding="utf-8") == "previous snapshot"


def test_primary_404_uses_mirror():
    source = {
        "id": "source",
        "url": "https://primary.invalid",
        "mirrors": ["https://mirror.invalid"],
    }

    class Response:
        def __init__(self, status, text=""):
            self.status_code = status
            self.text = text
            self.content = text.encode()
            self.encoding = "utf-8"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield self.content

    class Client:
        def stream(self, _method, url, **_kwargs):
            return Response(404) if "primary" in url else Response(200, "payload")

    _source, text, status = asyncio.run(fetcher._fetch_one(Client(), source))
    assert status == "ok"
    assert text == "payload"


def test_fetch_stream_stops_at_response_cap_and_uses_mirror(monkeypatch):
    source = {
        "id": "source",
        "url": "https://large.invalid",
        "mirrors": ["https://mirror.invalid"],
    }
    monkeypatch.setattr(fetcher, "MAX_RESPONSE_BYTES", 5)
    chunks_read = 0

    class Response:
        status_code = 200
        encoding = "utf-8"

        def __init__(self, chunks):
            self.chunks = chunks

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            nonlocal chunks_read
            for chunk in self.chunks:
                chunks_read += 1
                yield chunk

    class Client:
        def stream(self, _method, url, **_kwargs):
            if "large" in url:
                return Response([b"1234", b"5678", b"never-read"])
            return Response([b"ok"])

    _source, text, status = asyncio.run(fetcher._fetch_one(Client(), source))

    assert status == "ok"
    assert text == "ok"
    assert chunks_read == 3  # two large-source chunks, then one mirror chunk


def test_parse_rejects_unknown_disabled_and_non_object_records(monkeypatch, tmp_path):
    sources = _configure_temp_pipeline(monkeypatch, tmp_path)
    sources.append(
        {
            "id": "disabled",
            "url": "https://disabled.invalid",
            "format": "raw",
            "enabled": False,
        }
    )
    monkeypatch.setattr(cli, "_read_sources", lambda: sources)
    cli.STAGING.write_text(
        "\n".join(
            [
                json.dumps(
                    {"source_id": "fixture", "raw": _write_same_endpoint_nodes()}
                ),
                json.dumps(
                    {"source_id": "disabled", "raw": _write_same_endpoint_nodes()}
                ),
                json.dumps({"source_id": "unknown", "raw": "vless://x@y:443"}),
                "[]",
            ]
        ),
        encoding="utf-8",
    )

    summary = cli._parse_logic()

    assert summary["success"] is False
    assert summary["invalid_records"] == 1
    assert summary["rejected_sources"] == ["disabled", "unknown"]
    assert not cli.DB.exists()


def test_parse_restores_db_and_live_when_sources_activation_fails(
    monkeypatch, tmp_path
):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    sources_path = tmp_path / "state" / "sources.json"
    sources_path.write_text("[]\n", encoding="utf-8")
    monkeypatch.setattr(fetcher, "SOURCES_FILE", sources_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        old_rows = conn.execute(
            "SELECT uri,node_json FROM nodes ORDER BY uri"
        ).fetchall()
    old_live = cli.LIVE.read_bytes()
    old_sources = sources_path.read_bytes()

    cli.STAGING.write_text(
        json.dumps(
            {
                "source_id": "fixture",
                "raw": ("vless://00000000-0000-0000-0000-000000000099@new.example:443"),
            }
        ),
        encoding="utf-8",
    )

    def fail_save(_sources):
        raise OSError("simulated sources write failure")

    monkeypatch.setattr(fetcher, "save_sources", fail_save)
    summary = cli._parse_logic()

    assert summary["success"] is False
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        new_rows = conn.execute(
            "SELECT uri,node_json FROM nodes ORDER BY uri"
        ).fetchall()
    assert new_rows == old_rows
    assert cli.LIVE.read_bytes() == old_live
    assert sources_path.read_bytes() == old_sources


def test_vpnsuper_missing_handoff_retains_previous_staging(monkeypatch, tmp_path):
    staging = tmp_path / "staging.jsonl"
    staging.write_text("OLD", encoding="utf-8")
    sources = [
        {
            "id": "vpn",
            "url": "https://vpn.invalid",
            "format": "vpnsuper",
            "enabled": True,
        },
        {
            "id": "http",
            "url": "https://http.invalid",
            "format": "raw",
            "enabled": True,
        },
    ]
    monkeypatch.setattr(fetcher, "ROOT", tmp_path)
    monkeypatch.setattr(fetcher, "STAGING_FILE", staging)
    monkeypatch.setattr(fetcher, "load_sources", lambda: sources)
    monkeypatch.setattr(fetcher, "save_sources", lambda _sources: None)
    monkeypatch.setattr(fetcher, "_ua", lambda: "test")

    async def fake_harvest():
        return {"uris": 5}

    async def fake_fetch(_client, source):
        return source, "vless://id@host.example:443", "ok"

    monkeypatch.setattr(vpnsuper_feed, "harvest_async", fake_harvest)
    monkeypatch.setattr(vpnsuper_feed, "_merge_last_run", lambda _summary: None)
    monkeypatch.setattr(fetcher, "_fetch_one", fake_fetch)

    summary = asyncio.run(fetcher.fetch_all())

    assert summary["success"] is False
    assert summary["fetched"] == 1
    assert summary["total"] == 2
    assert summary["failed_sources"] == ["vpn"]
    assert staging.read_text(encoding="utf-8") == "OLD"


def test_emit_rejects_malformed_live_and_retains_outputs(monkeypatch, tmp_path):
    live = tmp_path / "live.jsonl"
    live.write_text(
        json.dumps(
            {
                "proto": "vless",
                "host": "edge.example",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "raw": (
                    "vless://00000000-0000-0000-0000-000000000001@edge.example:443"
                ),
                "alive": True,
            }
        )
        + "\n[]\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    old = {
        output_dir / "clash.yaml": "old clash",
        output_dir / "singbox.json": "old singbox",
        output_dir / "v2ray-base64.txt": "old v2ray",
        output_dir / "feed.xml": "old rss",
    }
    for path, content in old.items():
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(emit, "LIVE_FILE", live)
    monkeypatch.setattr(emit, "OUTPUT_DIR", output_dir)
    monkeypatch.setattr(emit, "FEED_FILE", output_dir / "feed.xml")

    summary = emit.emit_all()

    assert summary["success"] is False
    assert "line 2" in summary["error"]
    for path, content in old.items():
        assert path.read_text(encoding="utf-8") == content


def test_emit_rolls_back_every_output_when_activation_fails(monkeypatch, tmp_path):
    node = ProxyNode(
        proto="vless",
        host="edge.example",
        port=443,
        uuid="00000000-0000-0000-0000-000000000001",
        raw=("vless://00000000-0000-0000-0000-000000000001@edge.example:443"),
        alive=True,
    )
    live = tmp_path / "live.jsonl"
    live.write_text(json.dumps(node.model_dump(mode="json")), encoding="utf-8")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    old = {
        output_dir / "clash.yaml": "old clash",
        output_dir / "singbox.json": "old singbox",
        output_dir / "v2ray-base64.txt": "old v2ray",
        output_dir / "feed.xml": "old rss",
    }
    for path, content in old.items():
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(emit, "LIVE_FILE", live)
    monkeypatch.setattr(emit, "OUTPUT_DIR", output_dir)
    monkeypatch.setattr(emit, "FEED_FILE", output_dir / "feed.xml")

    original_replace = Path.replace

    def fail_second_activation(self, target):
        if self.name == "singbox.json.tmp":
            raise OSError("simulated activation failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_second_activation)
    summary = emit.emit_all()

    assert summary["success"] is False
    assert "activation failed" in summary["error"]
    for path, content in old.items():
        assert path.read_text(encoding="utf-8") == content


def test_verify_resume_fingerprint_changes_with_quality_config(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True
    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    quality = {
        "max_latency_ms": 1000,
        "min_download_speed_mbps": 5,
        "tier1_concurrent": 10,
        "tier2_concurrent": 2,
        "download_size_bytes": 1024,
    }
    monkeypatch.setattr(cli, "_load_quality", lambda: quality.copy())
    calls = 0

    def fake_prefilter(proxies):
        nonlocal calls
        calls += 1
        return {f"{proxy['server']}:{proxy['port']}" for proxy in proxies}

    monkeypatch.setattr(tcp_prefilter, "run", fake_prefilter)

    first = cli._verify_logic(max_runtime=-1)
    assert first["success"] is False
    progress = json.loads(
        (cli.STATE / "verify-progress.json").read_text(encoding="utf-8")
    )
    assert progress["schema_version"] == cli.VERIFY_PROGRESS_SCHEMA_VERSION
    first_fingerprint = progress["fingerprint"]

    quality["max_latency_ms"] = 500
    second = cli._verify_logic(max_runtime=-1)
    assert second["success"] is False
    updated = json.loads(
        (cli.STATE / "verify-progress.json").read_text(encoding="utf-8")
    )
    assert updated["fingerprint"] != first_fingerprint
    assert calls == 2


def test_d1_migrations_upgrade_the_original_schema(tmp_path):
    db = tmp_path / "legacy.db"
    original_schema = """
    CREATE TABLE nodes(
      id INTEGER PRIMARY KEY, uri TEXT NOT NULL UNIQUE,
      proto TEXT, host TEXT, port INTEGER, uuid TEXT, password TEXT,
      sni TEXT, net TEXT, country TEXT, latency_ms INTEGER,
      download_speed REAL, alive INTEGER, source TEXT, first_seen INTEGER,
      last_checked INTEGER, content_hash TEXT
    );
    CREATE TABLE sources(
      id TEXT PRIMARY KEY, url TEXT, format TEXT, enabled INTEGER,
      tier INTEGER, last_fetch INTEGER, last_count INTEGER, status TEXT
    );
    """
    migration_dir = Path(__file__).resolve().parents[1] / "infra" / "d1" / "migrations"
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.executescript(original_schema)
        conn.executescript(
            (migration_dir / "0002_atomic_snapshots.sql").read_text(encoding="utf-8")
        )
        conn.executescript(
            (migration_dir / "0003_full_node_model.sql").read_text(encoding="utf-8")
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(nodes)")}
        import_state = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='import_state'"
        ).fetchone()

    assert {
        "snapshot_id",
        "node_json",
        "alter_id",
        "protocol",
        "obfs",
        "congestion_control",
    } <= columns
    assert import_state == ("import_state",)


def test_fetch_restores_sources_when_staging_activation_fails(monkeypatch, tmp_path):
    staging = tmp_path / "staging.jsonl"
    staging.write_text("OLD", encoding="utf-8")
    sources_path = tmp_path / "sources.json"
    original_sources = [
        {
            "id": "source",
            "url": "https://source.invalid",
            "format": "raw",
            "enabled": True,
            "status": "old",
        }
    ]
    sources_path.write_text(
        json.dumps(original_sources, indent=2) + "\n", encoding="utf-8"
    )
    original_source_bytes = sources_path.read_bytes()
    monkeypatch.setattr(fetcher, "STAGING_FILE", staging)
    monkeypatch.setattr(fetcher, "SOURCES_FILE", sources_path)
    monkeypatch.setattr(fetcher, "load_sources", lambda: original_sources)
    monkeypatch.setattr(fetcher, "_ua", lambda: "test")

    async def fake_fetch(_client, source):
        return source, "vless://id@edge.example:443", "ok"

    monkeypatch.setattr(fetcher, "_fetch_one", fake_fetch)
    original_replace = Path.replace

    def fail_staging_activation(self, target):
        if self.name == "staging.jsonl.tmp":
            raise OSError("simulated staging activation failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_staging_activation)
    summary = asyncio.run(fetcher.fetch_all())

    assert summary["success"] is False
    assert "activation failed" in summary["error"]
    assert staging.read_text(encoding="utf-8") == "OLD"
    assert sources_path.read_bytes() == original_source_bytes
    assert not staging.with_suffix(".jsonl.tmp").exists()


def test_explicit_fixture_fallback_parses_end_to_end(monkeypatch, tmp_path):
    sources = _configure_temp_pipeline(monkeypatch, tmp_path)
    staging = cli.STAGING
    sources_path = tmp_path / "state" / "sources.json"
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    fixture = tmp_path / "sample-sub.txt"
    fixture.write_text(
        ("vless://00000000-0000-0000-0000-000000000001@fixture.example:443"),
        encoding="utf-8",
    )
    monkeypatch.setattr(fetcher, "STAGING_FILE", staging)
    monkeypatch.setattr(fetcher, "SOURCES_FILE", sources_path)
    monkeypatch.setattr(fetcher, "FIXTURE", fixture)
    monkeypatch.setattr(fetcher, "load_sources", lambda: sources)
    monkeypatch.setattr(fetcher, "_ua", lambda: "test")
    monkeypatch.setenv("ALLOW_FIXTURE_FALLBACK", "1")

    async def failed_fetch(_client, source):
        source["last_error"] = "offline"
        return source, None, "error"

    monkeypatch.setattr(fetcher, "_fetch_one", failed_fetch)
    fetch_summary = asyncio.run(fetcher.fetch_all())
    parse_summary = cli._parse_logic()

    assert fetch_summary["success"] is True
    assert fetch_summary["fallback_fixture"] is True
    assert parse_summary["success"] is True
    assert parse_summary["unique"] == 1


def test_verify_rolls_back_db_when_live_activation_fails(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True
    old_live = cli.LIVE.read_bytes()
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        documents = conn.execute("SELECT uri,node_json FROM nodes").fetchall()
        for uri, node_json in documents:
            document = json.loads(node_json)
            document["alive"] = True
            conn.execute(
                "UPDATE nodes SET alive=1,node_json=? WHERE uri=?",
                (json.dumps(document), uri),
            )
        conn.commit()

    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {
            "max_latency_ms": 1000,
            "min_download_speed_mbps": 5,
            "tier1_concurrent": 10,
            "tier2_concurrent": 2,
            "download_size_bytes": 1024,
        },
    )
    monkeypatch.setattr(
        tcp_prefilter,
        "run",
        lambda proxies: {f"{proxy['server']}:{proxy['port']}" for proxy in proxies},
    )

    def fake_run(args, **_kwargs):
        config = Path(args[args.index("-c") + 1])
        proxies = yaml.safe_load(config.read_text(encoding="utf-8"))["proxies"]
        if "-fast" in args:
            lines = [
                f"{index}.\t{proxy['name']}\t{proxy['type']}\t100ms"
                for index, proxy in enumerate(proxies, 1)
            ]
        else:
            lines = [
                (f"{index}.\t{proxy['name']}\t{proxy['type']}\t100ms\t0ms\t0%\t10MB/s")
                for index, proxy in enumerate(proxies, 1)
            ]
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    original_replace = Path.replace

    def fail_live_activation(self, target):
        if self.name == "live.jsonl.tmp":
            raise OSError("simulated live activation failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_live_activation)
    summary = cli._verify_logic()

    assert summary["success"] is False
    assert "activation failed" in summary["error"]
    assert cli.LIVE.read_bytes() == old_live
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        alive_values = {row[0] for row in conn.execute("SELECT alive FROM nodes")}
    assert alive_values == {1}


def test_vpnsuper_handoff_requires_timestamp_and_exact_uri_count(tmp_path):
    path = tmp_path / "vpnsuper_staging.jsonl"
    uri = "trojan://secret@edge.example:443"
    path.write_text(json.dumps({"source_id": "vpn", "raw": uri}), encoding="utf-8")
    with pytest.raises(ValueError, match="fetched_at"):
        fetcher._read_vpnsuper_record(path, "vpn", 1)

    path.write_text(
        json.dumps({"source_id": "vpn", "raw": uri, "fetched_at": 1}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="count"):
        fetcher._read_vpnsuper_record(path, "vpn", 2)


def test_unsupported_juicity_does_not_poison_verifier_batch(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    raw = "\n".join(
        [
            (
                "vless://00000000-0000-0000-0000-000000000001"
                "@edge.example:443?security=tls"
            ),
            (
                "juicity://00000000-0000-0000-0000-000000000002:secret"
                "@juicity.example:443?security=tls"
            ),
        ]
    )
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": raw}), encoding="utf-8"
    )
    assert cli._parse_logic()["success"] is True
    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {
            "max_latency_ms": 1000,
            "min_download_speed_mbps": 5,
            "tier1_concurrent": 10,
            "tier2_concurrent": 2,
            "download_size_bytes": 1024,
        },
    )
    monkeypatch.setattr(
        tcp_prefilter,
        "run",
        lambda proxies: {f"{proxy['server']}:{proxy['port']}" for proxy in proxies},
    )

    def fake_run(args, **_kwargs):
        config = Path(args[args.index("-c") + 1])
        proxy = yaml.safe_load(config.read_text(encoding="utf-8"))["proxies"][0]
        if "-fast" in args:
            output = f"1.\t{proxy['name']}\t{proxy['type']}\t100ms"
        else:
            output = f"1.\t{proxy['name']}\t{proxy['type']}\t100ms\t0ms\t0%\t10MB/s"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    summary = cli._verify_logic()

    assert summary["success"] is True
    assert summary["unsupported_for_verifier"] == 1
    records = [
        json.loads(line) for line in cli.LIVE.read_text(encoding="utf-8").splitlines()
    ]
    by_proto = {record["proto"]: record for record in records}
    assert by_proto["vless"]["alive"] is True
    assert by_proto["juicity"]["alive"] is False


def test_verify_isolates_one_stuck_proxy_process(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True
    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {
            "max_latency_ms": 1000,
            "min_download_speed_mbps": 5,
            "tier1_concurrent": 3,
            "tier2_concurrent": 2,
            "download_size_bytes": 1024,
            "probe_timeout_seconds": 1,
            "verifier_process_timeout_seconds": 2,
        },
    )
    monkeypatch.setattr(
        tcp_prefilter,
        "run",
        lambda proxies: {f"{proxy['server']}:{proxy['port']}" for proxy in proxies},
    )

    def fake_run(args, **_kwargs):
        config = Path(args[args.index("-c") + 1])
        proxy = yaml.safe_load(config.read_text(encoding="utf-8"))["proxies"][0]
        if "-fast" in args and proxy.get("uuid", "").endswith("2"):
            raise cli.subprocess.TimeoutExpired(args, 2)
        if "-fast" in args:
            output = f"1.\t{proxy['name']}\t{proxy['type']}\t100ms"
        else:
            output = f"1.\t{proxy['name']}\t{proxy['type']}\t100ms\t0ms\t0%\t10MB/s"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    summary = cli._verify_logic()

    assert summary["success"] is True
    assert summary["isolated_tier1_failures"] == 1
    records = [
        json.loads(line) for line in cli.LIVE.read_text(encoding="utf-8").splitlines()
    ]
    by_uuid = {record.get("uuid"): record for record in records}
    assert by_uuid["00000000-0000-0000-0000-000000000001"]["alive"] is True
    assert by_uuid["00000000-0000-0000-0000-000000000002"]["alive"] is False


def test_verify_retains_snapshot_when_every_isolated_process_stalls(
    monkeypatch, tmp_path
):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True
    old_live = cli.LIVE.read_bytes()
    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {
            "max_latency_ms": 1000,
            "min_download_speed_mbps": 5,
            "tier1_concurrent": 3,
            "tier2_concurrent": 2,
            "download_size_bytes": 1024,
            "probe_timeout_seconds": 1,
            "verifier_process_timeout_seconds": 2,
        },
    )
    monkeypatch.setattr(
        tcp_prefilter,
        "run",
        lambda proxies: {f"{proxy['server']}:{proxy['port']}" for proxy in proxies},
    )
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda args, **_kwargs: (_ for _ in ()).throw(
            cli.subprocess.TimeoutExpired(args, 2)
        ),
    )

    summary = cli._verify_logic()

    assert summary["success"] is False
    assert "no successful verifier process" in summary["error"]
    assert cli.LIVE.read_bytes() == old_live


def test_verify_rejects_header_only_output_and_retains_snapshot(monkeypatch, tmp_path):
    _configure_temp_pipeline(monkeypatch, tmp_path)
    cli.STAGING.write_text(
        json.dumps({"source_id": "fixture", "raw": _write_same_endpoint_nodes()}),
        encoding="utf-8",
    )
    assert cli._parse_logic()["success"] is True
    old_live = cli.LIVE.read_bytes()
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        old_rows = conn.execute(
            "SELECT uri,alive,latency_ms,download_speed,node_json FROM nodes ORDER BY uri"
        ).fetchall()

    monkeypatch.setattr(cli, "_find_speedtest_binary", lambda: "fake-speedtest")
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {
            "max_latency_ms": 1000,
            "min_download_speed_mbps": 5,
            "tier1_concurrent": 10,
            "tier2_concurrent": 2,
            "download_size_bytes": 1024,
        },
    )
    monkeypatch.setattr(
        tcp_prefilter,
        "run",
        lambda proxies: {f"{proxy['server']}:{proxy['port']}" for proxy in proxies},
    )
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="序号\t节点名称\t类型\t延迟",
            stderr="",
        ),
    )

    summary = cli._verify_logic()

    assert summary["success"] is False
    assert "recognized_rows=0" in summary["error"]
    assert cli.LIVE.read_bytes() == old_live
    with closing(sqlite3.connect(cli.DB)) as conn, conn:
        new_rows = conn.execute(
            "SELECT uri,alive,latency_ms,download_speed,node_json FROM nodes ORDER BY uri"
        ).fetchall()
    assert new_rows == old_rows
