from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.aggregator import scanner


def test_allowlist_accepts_literal_ip_and_rejects_broad_or_named_targets() -> None:
    assert scanner._normalize_allowlist(["127.0.0.1", "203.0.113.0/30"]) == [
        "127.0.0.1",
        "203.0.113.0/30",
    ]
    with pytest.raises(scanner.AllowlistError):
        scanner._normalize_allowlist(["example.test"])
    with pytest.raises(scanner.AllowlistError):
        scanner._normalize_allowlist(["0.0.0.0/0"])
    with pytest.raises(scanner.AllowlistError):
        scanner._normalize_allowlist(["203.0.113.1/24"])


def test_pipeline_filters_runner_output_to_allowlist_and_requested_ports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shards = tmp_path / "shards.txt"
    shards.write_text("127.0.0.1\n", encoding="utf-8")
    leads = tmp_path / "leads.jsonl"
    summaries: list[dict] = []
    seen_open_ports: list[scanner.OpenPort] = []

    monkeypatch.setattr(
        scanner,
        "_load_scan_config",
        lambda: {
            "enabled": True,
            "leads_only": True,
            "discovery_engine": "nmap",
            "ports_tcp": [8080],
            "rate": 100,
        },
    )
    monkeypatch.setattr(scanner, "LEADS_FILE", leads)
    monkeypatch.setattr(scanner, "_write_summary", summaries.append)

    def discover(_targets: list[str], _ports: list[int], _rate: int):
        return [
            scanner.OpenPort("127.0.0.1", 8080),
            scanner.OpenPort("198.51.100.7", 8080),
            scanner.OpenPort("127.0.0.1", 443),
        ]

    def fingerprint(open_ports: list[scanner.OpenPort]):
        seen_open_ports.extend(open_ports)
        return [
            scanner.ServiceInfo(host=item.host, port=item.port, service="http")
            for item in open_ports
        ]

    result = scanner.run(
        shards_file=shards,
        discovery_runner=discover,
        nmap_runner=fingerprint,
        enabled_override=True,
    )

    assert [(item.host, item.port) for item in seen_open_ports] == [("127.0.0.1", 8080)]
    assert result["open_ports"] == 1
    assert result["leads"] == 1
    assert result["success"] is True
    assert result["leads_only"] is True
    assert json.loads(leads.read_text(encoding="utf-8").splitlines()[0])["host"] == (
        "127.0.0.1"
    )
    assert summaries[-1]["reason"] == "completed"


def test_candidate_validation_is_injected_and_output_stays_quarantined(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shards = tmp_path / "shards.txt"
    shards.write_text("203.0.113.10\n", encoding="utf-8")
    leads = tmp_path / "leads.jsonl"
    quarantine = tmp_path / "scan-candidates.jsonl"
    gray_nodes = tmp_path / "gray_nodes.jsonl"
    summaries: list[dict] = []

    monkeypatch.setattr(
        scanner,
        "_load_scan_config",
        lambda: {
            "enabled": True,
            "leads_only": False,
            "discovery_engine": "nmap",
            "ports_tcp": [8388],
            "rate": 100,
        },
    )
    monkeypatch.setattr(scanner, "LEADS_FILE", leads)
    monkeypatch.setattr(scanner, "CANDIDATE_QUARANTINE", quarantine)
    monkeypatch.setattr(scanner, "GRAY_NODES", gray_nodes)
    monkeypatch.setattr(scanner, "_write_summary", summaries.append)

    def validator(candidate: scanner.CredentialCandidate):
        assert candidate.host == "203.0.113.10"
        assert candidate.protocol == "ss"
        return scanner.CandidateValidation(valid=True, detail="fixture-match")

    result = scanner.run(
        shards_file=shards,
        discovery_runner=lambda _targets, _ports, _rate: [
            scanner.OpenPort("203.0.113.10", 8388)
        ],
        nmap_runner=lambda _open: [],
        credential_validator=validator,
        enabled_override=True,
    )

    assert result["credential_candidates"] == 1
    assert result["candidates_quarantined"] == 1
    assert result["nodes_recovered"] == 1
    candidate = json.loads(quarantine.read_text(encoding="utf-8").splitlines()[0])
    assert candidate["validation_status"] == "verified"
    assert candidate["enabled"] is False
    assert candidate["review_status"] == "pending"
    gray = json.loads(gray_nodes.read_text(encoding="utf-8").splitlines()[0])
    assert gray["enabled"] is False
    assert gray["validation_status"] == "verified"


def test_nmap_fingerprint_groups_exact_host_ports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = tmp_path / "scan.xml"
    monkeypatch.setattr(scanner, "NMAP_OUT", output)
    monkeypatch.setattr(scanner, "_nmap_available", lambda: True)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs):
        commands.append(command)
        output.write_text(
            '<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="8080">'
            '<state state="open"/><service name="http"/></port></ports>'
            "</host></nmaprun>",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    result = scanner.run_nmap(
        [scanner.OpenPort("127.0.0.1", 8080), scanner.OpenPort("127.0.0.2", 443)]
    )

    assert len(commands) == 2
    port_args = [command[command.index("-p") + 1] for command in commands]
    assert sorted(port_args) == ["443", "8080"]
    assert {(service.host, service.port) for service in result} == {("127.0.0.1", 8080)}


def test_scan_summary_uses_canonical_stage_and_preserves_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(scanner, "ROOT", tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    last_run = state / "last-run.json"
    last_run.write_text(
        json.dumps({"stages": {"gray": {"counts": {"success": True}}}}),
        encoding="utf-8",
    )

    scanner._write_summary({"success": True, "reason": "completed", "ts": 123})

    document = json.loads(last_run.read_text(encoding="utf-8"))
    assert document["stage"] == 10
    assert document["last_stage_cmd"] == "scan-targets"
    assert document["counts"]["scan-targets"]["reason"] == "completed"
    assert set(document["stages"]) == {"gray", "scan-targets"}
