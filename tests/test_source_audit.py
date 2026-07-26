from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.aggregator import source_audit
from src.aggregator.parser import parse_uri
from src.aggregator.source_audit import (
    MAX_RESPONSE_BYTES,
    FetchResult,
    canonicalize_url,
    fetch_url,
    load_baseline,
    run,
    write_report,
)


UUID1 = "12345678-1234-1234-1234-123456789abc"
UUID2 = "22345678-1234-1234-1234-123456789abc"


def _uri(uuid: str, host: str, name: str = "") -> str:
    suffix = f"#{name}" if name else ""
    return f"vless://{uuid}@{host}:443?security=tls&sni={host}&type=tcp{suffix}"


def test_canonicalize_github_and_mirror_forms() -> None:
    expected = "https://raw.githubusercontent.com/Owner/Repo/main/configs/list.txt"
    assert (
        canonicalize_url("https://github.com/Owner/Repo/raw/main/configs/list.txt")
        == expected
    )
    assert (
        canonicalize_url("https://cdn.jsdelivr.net/gh/Owner/Repo@main/configs/list.txt")
        == expected
    )
    assert (
        canonicalize_url(
            "https://gh-proxy.com/https://raw.githubusercontent.com/Owner/Repo/main/configs/list.txt"
        )
        == expected
    )
    assert (
        canonicalize_url(
            "https://raw.githubusercontent.com/Owner/Repo/main/configs/list.txt/"
        )
        == expected
    )


def test_run_reports_semantic_delta_and_preserves_pipeline_files(
    tmp_path: Path,
) -> None:
    baseline_uri = _uri(UUID1, "baseline.example", "old-name")
    new_uri = _uri(UUID2, "new.example")
    baseline_node = parse_uri(baseline_uri)
    assert baseline_node is not None

    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "live.jsonl"
    output = tmp_path / "source-audit.json"
    staging = tmp_path / "staging.jsonl"
    db = tmp_path / "nodes.db"
    registry.write_text(
        json.dumps(
            {
                "id": "candidate-a",
                "url": "https://raw.githubusercontent.com/Owner/Repo/main/list.txt",
                "format": "raw",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text(
        json.dumps(baseline_node.model_dump(mode="json")) + "\n", encoding="utf-8"
    )
    staging.write_text("old staging\n", encoding="utf-8")
    db.write_bytes(b"old db")
    before = (baseline.read_bytes(), staging.read_bytes(), db.read_bytes())

    def fake_fetch(url: str, **_: object) -> FetchResult:
        body = baseline_uri + "\n" + new_uri + "\n"
        return FetchResult(
            url=url,
            ok=True,
            text=body,
            bytes_read=len(body.encode()),
            body_sha256="body",
        )

    report = run(registry, baseline, output, fetch_fn=fake_fetch)
    result = report["results"][0]
    assert result["parsed"] == 2
    assert result["unique"] == 2
    assert result["overlap"] == 1
    assert result["net_new"] == 1
    assert result["protocol_counts"] == {"vless": 2}
    assert len(result["sha256"]) == 64
    assert report["totals"]["net_new"] == 1
    assert json.loads(output.read_text(encoding="utf-8"))["run_id"] == report["run_id"]
    assert (baseline.read_bytes(), staging.read_bytes(), db.read_bytes()) == before
    assert not list(tmp_path.glob(".*.tmp"))


def test_fetcher_exception_is_reported_per_candidate(tmp_path: Path) -> None:
    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "live.jsonl"
    output = tmp_path / "source-audit.json"
    registry.write_text(
        json.dumps(
            {
                "id": "candidate-a",
                "url": "https://example.test/list.txt",
                "format": "raw",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text("", encoding="utf-8")

    def failing_fetcher(_url: str, **_kwargs: object) -> str:
        raise RuntimeError("upstream failed")

    report = run(registry, baseline, output, fetch_fn=failing_fetcher)

    assert report["success"] is False
    assert report["results"][0]["status"] == "fetch_error"
    assert report["results"][0]["errors"] == ["RuntimeError: upstream failed"]
    assert output.exists()


def test_mirror_jaccard_and_private_reserved_flag(tmp_path: Path) -> None:
    public_uri = _uri(UUID1, "public.example")
    private_uri = _uri(UUID2, "127.0.0.1")
    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "live.jsonl"
    output = tmp_path / "audit.json"
    primary = "https://raw.githubusercontent.com/o/r/main/list.txt"
    mirror = "https://cdn.jsdelivr.net/gh/o/r@main/list.txt"
    duplicate_mirror = (
        "https://gh-proxy.com/https://raw.githubusercontent.com/o/r/main/list.txt"
    )
    registry.write_text(
        json.dumps(
            {
                "id": "mirror",
                "url": primary,
                "format": "raw",
                "mirrors": [mirror, duplicate_mirror],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text("", encoding="utf-8")

    def fake_fetch(url: str, **_: object) -> str:
        return (public_uri + "\n" + private_uri) if url == primary else public_uri

    report = run(registry, baseline, output, fetch_fn=fake_fetch, mirror_jaccard=True)
    result = report["results"][0]
    assert result["mirror_jaccard"] == 0.5
    assert result["private_or_reserved"] is True
    assert result["private_reserved_count"] == 1
    assert result["private_reserved_hosts"] == ["127.0.0.1"]
    assert len(result["mirrors"]) == 1


def test_failed_primary_cannot_self_attest_mirror_parity(tmp_path: Path) -> None:
    uri = _uri(UUID1, "public.example")
    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "live.jsonl"
    output = tmp_path / "audit.json"
    primary = "https://example.test/primary"
    mirror = "https://cdn.example.test/mirror"
    registry.write_text(
        json.dumps(
            {
                "id": "fallback",
                "url": primary,
                "format": "raw",
                "mirrors": [mirror],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text("", encoding="utf-8")

    def fake_fetch(url: str, **_: object) -> FetchResult:
        if url == primary:
            return FetchResult(url=url, ok=False, status_code=503, error="upstream")
        return FetchResult(url=url, ok=True, status_code=200, text=uri)

    report = run(
        registry,
        baseline,
        output,
        fetch_fn=fake_fetch,
        mirror_jaccard=True,
    )

    result = report["results"][0]
    assert result["fetched_url"] == mirror
    assert result["mirror_jaccards"] == {mirror: None}
    assert result["mirror_jaccard"] is None
    assert result["mirrors"][0]["comparison_error"] == (
        "primary semantic set unavailable"
    )


def test_mirror_jaccard_uses_uncapped_semantic_set(tmp_path: Path) -> None:
    uris = [_uri(UUID1, "one.example"), _uri(UUID2, "two.example")]
    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "live.jsonl"
    output = tmp_path / "audit.json"
    primary = "https://raw.githubusercontent.com/o/r/main/list.txt"
    mirror = "https://cdn.jsdelivr.net/gh/o/r@main/list.txt"
    registry.write_text(
        json.dumps(
            {
                "id": "capped",
                "url": primary,
                "format": "raw",
                "max_nodes": 1,
                "mirrors": [mirror],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text("", encoding="utf-8")

    def fake_fetch(url: str, **_: object) -> str:
        return "\n".join(uris)

    report = run(
        registry,
        baseline,
        output,
        fetch_fn=fake_fetch,
        mirror_jaccard=True,
    )

    result = report["results"][0]
    assert result["unique"] == 1
    assert result["sampled_out"] == 1
    assert result["mirror_jaccard"] == 1.0


class _FakeResponse:
    status_code = 200
    headers = {}
    encoding = "utf-8"
    url = "https://example.test/large"

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def iter_bytes(self):
        yield from self.chunks


class _FakeStream:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, *_args):
        return None


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response

    def stream(self, *_args, **_kwargs):
        return _FakeStream(self.response)


def test_fetch_url_enforces_stream_cap() -> None:
    response = _FakeResponse([b"x" * (MAX_RESPONSE_BYTES - 1), b"yy"])
    result = fetch_url(
        "https://example.test/large",
        client=_FakeClient(response),
        max_bytes=MAX_RESPONSE_BYTES,
    )
    assert result.ok is False
    assert result.too_large is True
    assert result.bytes_read > MAX_RESPONSE_BYTES


def test_published_singbox_output_is_supported_as_read_only_baseline(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "singbox.json"
    baseline.write_text(
        json.dumps(
            {
                "outbounds": [
                    {
                        "type": "vless",
                        "tag": "baseline",
                        "server": "baseline.example",
                        "server_port": 443,
                        "uuid": UUID1,
                        "tls": {
                            "enabled": True,
                            "server_name": "baseline.example",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    nodes, invalid, error = load_baseline(baseline)

    assert error is None
    assert invalid == 0
    assert len(nodes) == 1
    assert nodes[0].host == "baseline.example"


def test_unsupported_uri_entries_are_included_in_ratio(tmp_path: Path) -> None:
    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "live.jsonl"
    output = tmp_path / "audit.json"
    registry.write_text(
        json.dumps(
            {
                "id": "mixed",
                "url": "https://example.test/mixed.txt",
                "format": "raw",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text("", encoding="utf-8")
    body = _uri(UUID1, "public.example") + "\nhttp://user:pass@proxy.example:8080\n"

    report = run(
        registry,
        baseline,
        output,
        fetch_fn=lambda url, **_: FetchResult(
            url=url,
            ok=True,
            text=body,
            status_code=200,
        ),
    )

    result = report["results"][0]
    assert result["candidate_entries"] == 2
    assert result["parsed"] == 1
    assert result["unsupported_or_invalid"] == 1
    assert result["unsupported_ratio"] == 0.5


def test_atomic_report_replace_keeps_previous_output_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "source-audit.json"
    output.write_text("previous\n", encoding="utf-8")

    def fail_replace(_source: str, _destination: str) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(source_audit.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        write_report({"version": 1}, output)
    assert output.read_text(encoding="utf-8") == "previous\n"
    assert not list(tmp_path.glob(".*.tmp"))


def test_history_cannot_target_pipeline_snapshot() -> None:
    with pytest.raises(ValueError, match="pipeline snapshot"):
        source_audit.write_history(source_audit.DEFAULT_BASELINE_PATH, [])


def test_audit_cannot_overwrite_output_or_baseline(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pipeline snapshot"):
        source_audit.write_report(
            {"version": 1}, source_audit.ROOT / "output" / "singbox.json"
        )

    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "baseline.jsonl"
    registry.write_text(
        json.dumps(
            {
                "id": "candidate",
                "url": "https://example.test/list.txt",
                "format": "raw",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    baseline.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="read-only baseline"):
        run(registry, baseline, baseline, fetch_fn=lambda *_args, **_kwargs: "")


def test_audit_destinations_cannot_collide_with_custom_inputs(tmp_path: Path) -> None:
    registry = tmp_path / "candidates.jsonl"
    baseline = tmp_path / "baseline.jsonl"
    output = tmp_path / "audit.json"
    history = tmp_path / "history.jsonl"
    registry.write_text("", encoding="utf-8")
    baseline.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="history.*read-only baseline"):
        run(registry, baseline, output, history_path=baseline)
    with pytest.raises(ValueError, match="output and history"):
        run(registry, baseline, output, history_path=output)
    with pytest.raises(ValueError, match="candidate registry"):
        run(registry, baseline, registry, history_path=history)
