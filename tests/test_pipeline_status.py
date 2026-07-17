from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aggregator import cli, emit
from aggregator.models import ProxyNode


FIXED_TIME = "2026-07-17T10:00:00Z"


def _node(*, suffix: str, alive: bool | None, secret: str) -> ProxyNode:
    return ProxyNode(
        proto="vless",
        host=f"edge-{suffix}.example",
        port=443,
        uuid=f"00000000-0000-0000-0000-{suffix:0>12}",
        raw=(
            f"vless://00000000-0000-0000-0000-{suffix:0>12}"
            f"@edge-{suffix}.example:443?token={secret}"
        ),
        alive=alive,
        latency_ms=100 if alive is True else None,
        download_speed=10 if alive is True else None,
    )


def _verify_summary(live_file: Path, *, alive: int, unverified: int = 0) -> dict:
    return {
        "success": True,
        "completed": True,
        "tier1_alive": alive,
        "tier2_passed": alive,
        "total_alive": alive,
        "unverified": unverified,
        "live_snapshot_sha256": hashlib.sha256(live_file.read_bytes()).hexdigest(),
    }


def _configure_emitter(
    monkeypatch, tmp_path: Path, nodes: list[ProxyNode]
) -> tuple[Path, Path]:
    live = tmp_path / "state" / "live.jsonl"
    live.parent.mkdir()
    live.write_text(
        "".join(
            json.dumps(node.model_dump(mode="json"), ensure_ascii=False) + "\n"
            for node in nodes
        ),
        encoding="utf-8",
    )
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setattr(emit, "LIVE_FILE", live)
    monkeypatch.setattr(emit, "OUTPUT_DIR", output)
    monkeypatch.setattr(emit, "FEED_FILE", output / "feed.xml")
    monkeypatch.setattr(emit, "_utc_rfc3339", lambda: FIXED_TIME)
    return live, output


def test_healthy_status_is_deterministic_and_contains_only_counts() -> None:
    secret = "super-secret-token"
    nodes = [
        _node(suffix="1", alive=True, secret=secret),
        _node(suffix="2", alive=False, secret=secret),
    ]
    document = emit._pipeline_status_document(
        nodes,
        verify_summary={
            "success": True,
            "completed": True,
            "tier1_alive": 1,
            "tier2_passed": 1,
            "total_alive": 1,
            "unverified": 0,
        },
        clash_proxies=1,
        singbox_outbounds=1,
        rss_items=1,
        generated_at=FIXED_TIME,
    )

    assert document == {
        "schema_version": 1,
        "generated_at": FIXED_TIME,
        "pipeline_status": "healthy",
        "verify": {
            "total": 2,
            "verified": 2,
            "alive": 1,
            "dead": 1,
            "unverified": 0,
            "tier1_alive": 1,
            "tier2_passed": 1,
            "completed": True,
        },
        "artifacts": {
            "node_count": 1,
            "clash_proxies": 1,
            "singbox_outbounds": 1,
            "rss_items": 1,
        },
    }
    serialized = json.dumps(document)
    assert secret not in serialized
    assert "vless://" not in serialized
    assert "error" not in serialized


def test_unknown_bootstrap_is_schema_valid_but_not_ci_healthy() -> None:
    document = {
        "schema_version": 1,
        "generated_at": FIXED_TIME,
        "pipeline_status": "unknown",
        "verify": {
            "total": 1084,
            "verified": 0,
            "alive": 0,
            "dead": 0,
            "unverified": 1084,
            "tier1_alive": 0,
            "tier2_passed": 0,
            "completed": False,
        },
        "artifacts": {
            "node_count": 78,
            "clash_proxies": 78,
            "singbox_outbounds": 78,
            "rss_items": 78,
        },
    }

    assert emit.validate_pipeline_status(document) is document


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"schema_version": True}),
        lambda value: value.update({"pipeline_status": {"healthy": True}}),
        lambda value: value.update({"raw_uri": "vless://secret"}),
        lambda value: value["verify"].update({"error": "token=secret"}),
        lambda value: value["verify"].update({"completed": 1}),
    ],
)
def test_status_schema_rejects_extension_fields_and_integer_booleans(mutation) -> None:
    document = {
        "schema_version": 1,
        "generated_at": FIXED_TIME,
        "pipeline_status": "healthy",
        "verify": {
            "total": 1,
            "verified": 1,
            "alive": 1,
            "dead": 0,
            "unverified": 0,
            "tier1_alive": 1,
            "tier2_passed": 1,
            "completed": True,
        },
        "artifacts": {
            "node_count": 1,
            "clash_proxies": 1,
            "singbox_outbounds": 1,
            "rss_items": 1,
        },
    }
    mutation(document)

    with pytest.raises(emit.InvalidPipelineStatus):
        emit.validate_pipeline_status(document)


def test_emit_activates_healthy_status_with_exact_artifact_counts(
    monkeypatch, tmp_path: Path
) -> None:
    secret = "credential-must-not-leak"
    live, output = _configure_emitter(
        monkeypatch,
        tmp_path,
        [
            _node(suffix="1", alive=True, secret=secret),
            _node(suffix="2", alive=False, secret=secret),
        ],
    )

    summary = emit.emit_all(verify_summary=_verify_summary(live, alive=1))

    assert summary["success"] is True
    assert summary["pipeline_status"] == "healthy"
    status_text = (output / "pipeline-status.json").read_text(encoding="utf-8")
    assert secret not in status_text
    assert "vless://" not in status_text
    validated = emit.validate_pipeline_status_artifact(output, require_healthy=True)
    assert validated["node_count"] == 1


def test_direct_emit_activates_matching_unknown_status(
    monkeypatch, tmp_path: Path
) -> None:
    _live, output = _configure_emitter(
        monkeypatch,
        tmp_path,
        [_node(suffix="1", alive=True, secret="fixture")],
    )

    summary = emit.emit_all()

    assert summary["success"] is True
    assert summary["pipeline_status"] == "unknown"
    assert emit.validate_pipeline_status_artifact(output)["node_count"] == 1
    with pytest.raises(emit.InvalidPipelineStatus, match="not healthy"):
        emit.validate_pipeline_status_artifact(output, require_healthy=True)


def test_status_hash_mismatch_retains_entire_previous_snapshot(
    monkeypatch, tmp_path: Path
) -> None:
    live, output = _configure_emitter(
        monkeypatch,
        tmp_path,
        [_node(suffix="1", alive=True, secret="fixture")],
    )
    old = {
        output / "clash.yaml": b"old clash",
        output / "singbox.json": b"old singbox",
        output / "v2ray-base64.txt": b"old v2ray",
        output / "feed.xml": b"old rss",
        output / "pipeline-status.json": b"old status",
    }
    for path, content in old.items():
        path.write_bytes(content)
    summary = _verify_summary(live, alive=1)
    summary["live_snapshot_sha256"] = "0" * 64

    result = emit.emit_all(verify_summary=summary)

    assert result["success"] is False
    assert "does not match" in result["error"]
    assert {path: path.read_bytes() for path in old} == old


def test_status_activation_failure_rolls_back_all_five_files(
    monkeypatch, tmp_path: Path
) -> None:
    live, output = _configure_emitter(
        monkeypatch,
        tmp_path,
        [_node(suffix="1", alive=True, secret="fixture")],
    )
    old = {
        output / "clash.yaml": b"old clash",
        output / "singbox.json": b"old singbox",
        output / "v2ray-base64.txt": b"old v2ray",
        output / "feed.xml": b"old rss",
        output / "pipeline-status.json": b"old status",
    }
    for path, content in old.items():
        path.write_bytes(content)
    original_replace = Path.replace

    def fail_status_activation(self: Path, target: Path) -> Path:
        if self.name == "pipeline-status.json.tmp":
            raise OSError("simulated status activation failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_status_activation)

    result = emit.emit_all(verify_summary=_verify_summary(live, alive=1))

    assert result["success"] is False
    assert "activation failed" in result["error"]
    assert {path: path.read_bytes() for path in old} == old


def test_cli_completed_verify_loader_is_immediate_and_closed(
    monkeypatch, tmp_path: Path
) -> None:
    last_run = tmp_path / "last-run.json"
    monkeypatch.setattr(cli, "LAST_RUN", last_run)
    summary = {"success": True, "completed": True, "tier1_alive": 1}
    last_run.write_text(
        json.dumps(
            {
                "last_stage_cmd": "verify",
                "counts": {"verify": summary},
                "ts": 1,
                "stage": 1,
            }
        ),
        encoding="utf-8",
    )
    assert cli._load_completed_verify_summary() == (summary, None)

    last_run.write_text(
        json.dumps(
            {
                "last_stage_cmd": "publish",
                "counts": {"publish": {"success": True}},
            }
        ),
        encoding="utf-8",
    )
    loaded, error = cli._load_completed_verify_summary()
    assert loaded is None
    assert "immediately follow" in (error or "")


def test_workflows_validate_commit_upload_and_deploy_pipeline_status() -> None:
    root = Path(__file__).resolve().parents[1]
    fetch = (root / ".github/workflows/fetch.yml").read_text(encoding="utf-8")
    daily = (root / ".github/workflows/verify-daily.yml").read_text(encoding="utf-8")
    deploy = (root / ".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")

    for workflow in (fetch, daily):
        assert "python src/aggregator/cli.py validate-output-status" in workflow
        assert "output/pipeline-status.json" in workflow
        assert "pipeline-status.json; do" in workflow
    assert "['fetch-and-publish', 'verify-daily']" in deploy
    assert "output/pipeline-status.json" in deploy
    assert "type(status['schema_version']) is int" in deploy
    assert "path: ${{ runner.temp }}/published-output" in deploy
    assert 'source_dir="$RUNNER_TEMP/published-output"' in deploy
    assert 'find "$source_dir" -mindepth 1 -maxdepth 1 | wc -l' in deploy
    assert '" -eq 7' in deploy
    assert "root = pathlib.Path('pages-input')" in deploy
    assert "PyYAML==6.0.3" in deploy
    assert "artifacts['clash_proxies'] == len(clash['proxies'])" in deploy
    assert "artifacts['rss_items'] == artifacts['node_count']" in deploy
    assert "artifacts['singbox_outbounds'] <= artifacts['node_count']" in deploy
    assert "verify['total'] > 0" in deploy
    assert 'cmp - "pages-input/${artifact#output/}"' in deploy
    assert '" -eq 6' in deploy
    assert 'run: test -n "$PAGES_PRODUCTION_BRANCH"' in deploy
    assert "--branch=${{ vars.PAGES_PRODUCTION_BRANCH }}" in deploy


def test_tracked_pipeline_status_matches_current_output_snapshot() -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / "output"

    summary = emit.validate_pipeline_status_artifact(output)
    document = json.loads((output / "pipeline-status.json").read_text(encoding="utf-8"))

    assert summary["success"] is True
    assert set(document) == {
        "schema_version",
        "generated_at",
        "pipeline_status",
        "verify",
        "artifacts",
    }
    serialized = json.dumps(document)
    for forbidden in ("vless://", "vmess://", "trojan://", "password", "token"):
        assert forbidden not in serialized
