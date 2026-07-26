from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aggregator import cli
from aggregator.parser import parse_uri


def _report(
    run_id: str,
    generated_at: str,
    *,
    passed: bool = True,
    baseline_sha256: str = "baseline-a",
    baseline_count: int = 100,
    body_sha256: str = "body-a",
    node_set_sha256: str = "nodes-a",
    semantic_sha256: str = "semantic-a",
) -> dict:
    return {
        "run_id": run_id,
        "generated_at": generated_at,
        "verify_enabled": True,
        "baseline": {"sha256": baseline_sha256, "nodes": baseline_count},
        "results": [
            {
                "id": "candidate-a",
                "body_sha256": body_sha256,
                "content_sha256": body_sha256,
                "node_set_sha256": node_set_sha256,
                "sha256": semantic_sha256,
                "unique": 10,
                "unique_before_cap": 12,
                "sampled_out": 2,
                "capped": True,
                "gate": {"passed": passed, "reasons": [] if passed else ["failed"]},
                "verification": {
                    "tier1_alive": 5,
                    "tier2_passed": 5,
                    "net_new_tier2": 5,
                },
            }
        ],
        "gate": {"passed": passed, "reasons": [] if passed else ["failed"]},
    }


def test_promotion_history_requires_three_runs_and_48_hours(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    start = datetime(2026, 7, 20, tzinfo=timezone.utc)

    first = cli._update_canary_history(
        _report("run-1", start.strftime("%Y-%m-%dT%H:%M:%SZ")),
        history_path=history,
        candidate_set_sha256="set-a",
    )
    second = cli._update_canary_history(
        _report(
            "run-2",
            (start + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        history_path=history,
        candidate_set_sha256="set-a",
    )
    third = cli._update_canary_history(
        _report(
            "run-3",
            (start + timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        history_path=history,
        candidate_set_sha256="set-a",
    )

    assert first["promotion_ready"] is False
    assert second["promotion_ready"] is False
    assert third["promotion_ready"] is True
    assert third["results"][0]["promotion_history"]["successful_runs"] == 3
    assert third["results"][0]["promotion_history"]["window_hours"] == 48.0

    entries = [json.loads(line) for line in history.read_text().splitlines()]
    assert len(entries) == 3
    assert all("tier1_alive_keys" not in entry for entry in entries)


def test_history_fingerprint_change_does_not_count_old_runs(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    start = datetime(2026, 7, 20, tzinfo=timezone.utc)
    for index in range(3):
        cli._update_canary_history(
            _report(
                f"run-{index}",
                (start + timedelta(hours=index * 24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
            history_path=history,
            candidate_set_sha256="set-a",
        )

    current = cli._update_canary_history(
        _report(
            "run-new", (start + timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        history_path=history,
        candidate_set_sha256="set-b",
    )

    assert current["promotion_ready"] is False
    assert current["results"][0]["promotion_history"]["successful_runs"] == 1


def test_candidate_fingerprint_binds_round_context() -> None:
    record = {
        "id": "candidate-a",
        "url": "https://example.test/source",
        "format": "raw",
        "candidate_round": 1,
        "max_nodes": 10,
        "sample_strategy": "stable_hash",
    }
    round_one = cli._candidate_set_fingerprint([record], {"round_number": 1})
    round_two = cli._candidate_set_fingerprint([record], {"round_number": 2})
    assert round_one != round_two


def test_history_content_or_baseline_change_resets_streak(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    start = datetime(2026, 7, 20, tzinfo=timezone.utc)
    candidate_fingerprints = {"candidate-a": "candidate-config-a"}
    for index in range(3):
        cli._update_canary_history(
            _report(
                f"stable-{index}",
                (start + timedelta(hours=index * 24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
            history_path=history,
            candidate_set_sha256="set-a",
            candidate_fingerprints=candidate_fingerprints,
        )

    baseline_changed = cli._update_canary_history(
        _report(
            "baseline-changed",
            (start + timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            baseline_sha256="baseline-b",
            baseline_count=101,
        ),
        history_path=history,
        candidate_set_sha256="set-a",
        candidate_fingerprints=candidate_fingerprints,
    )
    assert baseline_changed["promotion_ready"] is False
    assert baseline_changed["results"][0]["promotion_history"]["successful_runs"] == 1

    upstream_changed = cli._update_canary_history(
        _report(
            "upstream-changed",
            (start + timedelta(hours=96)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            baseline_sha256="baseline-b",
            baseline_count=101,
            body_sha256="body-b",
            node_set_sha256="nodes-b",
            semantic_sha256="semantic-b",
        ),
        history_path=history,
        candidate_set_sha256="set-a",
        candidate_fingerprints=candidate_fingerprints,
    )
    assert upstream_changed["promotion_ready"] is False
    assert upstream_changed["results"][0]["promotion_history"]["successful_runs"] == 1

    reverted = cli._update_canary_history(
        _report(
            "upstream-reverted",
            (start + timedelta(hours=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            baseline_sha256="baseline-b",
            baseline_count=101,
        ),
        history_path=history,
        candidate_set_sha256="set-a",
        candidate_fingerprints=candidate_fingerprints,
    )
    assert reverted["promotion_ready"] is False
    assert reverted["results"][0]["promotion_history"]["successful_runs"] == 1

    entries = [json.loads(line) for line in history.read_text().splitlines()]
    projection = entries[-2]["candidate_projections"]["candidate-a"]
    assert projection["baseline_sha256"] == "baseline-b"
    assert projection["body_sha256"] == "body-b"
    assert projection["node_set_sha256"] == "nodes-b"
    assert projection["sample_projection_sha256"]
    assert entries[-2]["candidate_fingerprints"] == candidate_fingerprints
    assert entries[-2]["candidate_history_fingerprints"]["candidate-a"]


def test_failed_verified_run_resets_candidate_streak(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    start = datetime(2026, 7, 20, tzinfo=timezone.utc)
    reports = [
        ("run-1", 0, True),
        ("run-2", 24, True),
        ("run-3", 48, False),
        ("run-4", 72, True),
        ("run-5", 96, True),
        ("run-6", 120, True),
    ]
    latest = None
    for run_id, hours, passed in reports:
        latest = cli._update_canary_history(
            _report(
                run_id,
                (start + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                passed=passed,
            ),
            history_path=history,
            candidate_set_sha256="set-a",
        )
        if run_id == "run-3":
            assert latest["results"][0]["promotion_history"]["successful_runs"] == 0

    assert latest is not None
    assert latest["promotion_ready"] is True
    assert latest["results"][0]["promotion_history"]["successful_runs"] == 3
    assert latest["results"][0]["promotion_history"]["window_hours"] == 48.0


def test_single_candidate_can_reuse_batch_history_projection(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    start = datetime(2026, 7, 20, tzinfo=timezone.utc)
    candidate_fingerprint = {"candidate-a": "candidate-a-fingerprint"}
    for index in range(3):
        cli._update_canary_history(
            _report(
                f"batch-{index}",
                (start + timedelta(hours=index * 24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
            history_path=history,
            candidate_set_sha256="batch-set",
            candidate_fingerprints=candidate_fingerprint,
        )

    current = cli._update_canary_history(
        _report("single", (start + timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        history_path=history,
        candidate_set_sha256="single-set",
        candidate_fingerprints=candidate_fingerprint,
    )

    assert current["promotion_ready"] is True
    assert current["results"][0]["promotion_history"]["successful_runs"] == 4


def test_round_one_promotion_requires_batch_diversity_evidence(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    start = datetime(2026, 7, 20, tzinfo=timezone.utc)
    for index in range(3):
        report = _report(
            f"single-{index}",
            (start + timedelta(hours=index * 24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        result = cli._update_canary_history(
            report,
            history_path=history,
            candidate_set_sha256="single-set",
            candidate_fingerprints={"candidate-a": "candidate-a-fingerprint"},
            candidate_diversity_requirements={"candidate-a": True},
        )
    assert result["promotion_ready"] is False
    assert (
        result["results"][0]["promotion_history"]["batch_diversity_evidence"] is False
    )


def test_low_jaccard_mirror_is_excluded_without_rejecting_primary(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "live.jsonl"
    baseline.write_text("", encoding="utf-8")
    report = {
        "baseline_error": None,
        "totals": {"net_new": 10},
        "results": [
            {
                "id": "candidate-a",
                "url": "https://example.test/primary",
                "fetched_url": "https://example.test/primary",
                "status": "ok",
                "http_status": 200,
                "unique": 10,
                "unsupported_ratio": 0.1,
                "private_reserved_count": 0,
                "overlap_ratio": 0.0,
                "mirror_jaccards": {"https://example.test/mirror": 0.5},
            }
        ],
    }

    result = cli._apply_canary_gates(
        report,
        verify_enabled=False,
        baseline_path=baseline,
    )

    assert result["gate"]["passed"] is True
    assert result["results"][0]["mirror_policy"]["production_eligible"] == []
    assert result["results"][0]["mirror_policy"]["rejected"] == [
        "https://example.test/mirror"
    ]


def test_isolated_verifier_restores_production_paths(monkeypatch) -> None:
    node = parse_uri(
        "vless://12345678-1234-1234-1234-123456789abc@edge.example:443"
        "?security=tls&sni=edge.example&type=tcp"
    )
    assert node is not None
    original = (cli.STATE, cli.DB, cli.LIVE, cli.LAST_RUN)

    def fake_verify(*, max_runtime=None):
        cli.LIVE.write_text("", encoding="utf-8")
        return {
            "completed": True,
            "success": True,
            "tier1_tested": 1,
            "tier1_alive": 0,
            "tier2_tested": 0,
            "tier2_passed": 0,
        }

    monkeypatch.setattr(cli, "_verify_logic", fake_verify)
    summary = cli._verify_candidate_isolated([node])

    assert summary["success"] is True
    assert (cli.STATE, cli.DB, cli.LIVE, cli.LAST_RUN) == original
