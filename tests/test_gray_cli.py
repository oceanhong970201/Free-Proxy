from __future__ import annotations

from typer.testing import CliRunner

from aggregator import cli


runner = CliRunner()


def test_gray_crawl_command_reports_summary(monkeypatch):
    monkeypatch.setattr(
        cli.gray_sources,
        "run",
        lambda: {
            "success": True,
            "panels_found": 2,
            "leads_written": 2,
            "nodes_collected": 0,
        },
    )

    result = runner.invoke(cli.app, ["gray-crawl"])

    assert result.exit_code == 0
    assert "gray-crawl summary" in result.stdout
    assert "panels_found" in result.stdout


def test_scan_targets_command_passes_explicit_overrides(monkeypatch, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("127.0.0.1\n", encoding="utf-8")
    captured: dict = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"success": True, "leads": 1, "nodes_recovered": 0}

    monkeypatch.setattr(cli.scanner, "run", fake_run)

    result = runner.invoke(
        cli.app,
        [
            "scan-targets",
            "--shards",
            str(targets),
            "--ports",
            "8388,443,443",
            "--rate",
            "25",
            "--force",
        ],
    )

    assert result.exit_code == 0
    assert captured == {
        "shards_file": targets,
        "ports": [443, 8388],
        "rate": 25,
        "enabled_override": True,
    }


def test_scan_targets_command_rejects_invalid_ports():
    result = runner.invoke(cli.app, ["scan-targets", "--ports", "443,nope"])

    assert result.exit_code == 2
    assert "ports must be comma-separated integers" in result.output
