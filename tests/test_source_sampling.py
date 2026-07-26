from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from aggregator import cli, fetcher
from aggregator.models import ProxyNode, Source


def _configure_pipeline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, max_nodes: int | None
) -> list[dict]:
    state = tmp_path / "state"
    state.mkdir()
    schema_dir = tmp_path / "infra" / "d1"
    schema_dir.mkdir(parents=True)
    workspace = Path(__file__).resolve().parents[1]
    (schema_dir / "schema.sql").write_text(
        (workspace / "infra" / "d1" / "schema.sql").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "STATE", state)
    monkeypatch.setattr(cli, "DB", tmp_path / "nodes.db")
    monkeypatch.setattr(cli, "STAGING", state / "staging.jsonl")
    monkeypatch.setattr(cli, "LIVE", state / "live.jsonl")
    monkeypatch.setattr(cli, "LAST_RUN", state / "last-run.json")

    source = {
        "id": "sampled",
        "url": "https://example.invalid/sub",
        "format": "raw",
        "enabled": True,
        "tier": 1,
        "max_nodes": max_nodes,
        "sample_strategy": "stable_hash",
        "status": "ok",
    }
    sources = [source]
    monkeypatch.setattr(cli, "_read_sources", lambda: sources)
    monkeypatch.setattr(fetcher, "SOURCES_FILE", state / "sources.json")
    monkeypatch.setattr(fetcher, "save_sources", lambda _sources: None)
    return sources


def _uri(index: int, *, name: str | None = None) -> str:
    node_id = UUID(int=index)
    fragment = name or f"node-{index}"
    return (
        f"vless://{node_id}@edge-{index}.example:443"
        f"?security=tls&type=ws&path=%2F{index}#{fragment}"
    )


def _write_staging(raw: str) -> None:
    cli.STAGING.write_text(
        json.dumps({"source_id": "sampled", "raw": raw}), encoding="utf-8"
    )


def _live_keys() -> set[str]:
    records = [
        json.loads(line) for line in cli.LIVE.read_text(encoding="utf-8").splitlines()
    ]
    return {ProxyNode(**record).dedup_key() for record in records}


def test_source_sampling_schema_is_bounded_and_closed() -> None:
    source = Source(id="source", url="https://example.invalid", format="raw")
    assert source.max_nodes is None
    assert source.sample_strategy == "stable_hash"

    bounded = Source(
        id="source",
        url="https://example.invalid",
        format="raw",
        max_nodes=25,
        sample_strategy="stable_hash",
    )
    assert bounded.max_nodes == 25

    with pytest.raises(ValidationError):
        Source(id="source", url="https://example.invalid", format="raw", max_nodes=0)
    with pytest.raises(ValidationError):
        Source(id="source", url="https://example.invalid", format="raw", max_nodes=True)
    with pytest.raises(ValidationError):
        Source(id="source", url="https://example.invalid", format="raw", max_nodes="25")
    with pytest.raises(ValidationError):
        Source(
            id="source",
            url="https://example.invalid",
            format="raw",
            sample_strategy="first",
        )


def test_parse_samples_after_source_dedupe_and_updates_last_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sources = _configure_pipeline(monkeypatch, tmp_path, max_nodes=2)
    monkeypatch.setattr(cli, "_load_quality", lambda: {"max_total_nodes": 10})
    uris = [_uri(index) for index in range(1, 5)]
    uris.append(_uri(1, name="semantic-duplicate"))

    _write_staging("\n".join(uris))
    first = cli._parse_logic()
    first_keys = _live_keys()

    assert first["success"] is True
    assert first["raw_nodes"] == 5
    assert first["sampled"] == 2
    assert first["unique"] == 2
    assert first["duplicates"] == 1
    assert first["by_source"] == {"sampled": 2}
    assert first["truncated_by_source"] == {"sampled": 2}
    assert sources[0]["last_count"] == 2
    with closing(sqlite3.connect(cli.DB)) as conn:
        assert conn.execute(
            "SELECT last_count FROM sources WHERE id='sampled'"
        ).fetchone() == (2,)

    _write_staging("\n".join(reversed(uris)))
    second = cli._parse_logic()

    assert second["success"] is True
    assert _live_keys() == first_keys


def test_parse_total_caps_fail_closed_and_canary_uses_smaller_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sources = _configure_pipeline(monkeypatch, tmp_path, max_nodes=None)
    cli.LIVE.write_text("prior snapshot\n", encoding="utf-8")
    old_live = cli.LIVE.read_bytes()
    monkeypatch.setattr(
        cli,
        "_load_quality",
        lambda: {"max_total_nodes": 4, "canary_max_total_nodes": 2},
    )
    monkeypatch.setenv("SOURCE_CANARY", "1")
    _write_staging("\n".join(_uri(index) for index in range(1, 4)))

    summary = cli._parse_logic()

    assert summary["success"] is False
    assert summary["sampled"] == 3
    assert "canary_max_total_nodes=2" in summary["error"]
    assert cli.LIVE.read_bytes() == old_live
    assert not cli.DB.exists()
    assert "last_count" not in sources[0]

    monkeypatch.delenv("SOURCE_CANARY")
    assert cli._parse_logic()["success"] is True
