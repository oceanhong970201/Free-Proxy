from __future__ import annotations

import json
from pathlib import Path

from aggregator import source_audit


ROOT = Path(__file__).resolve().parents[1]


def test_candidate_registry_has_fixed_disabled_shape_and_round_cap() -> None:
    path = ROOT / "state" / "candidates.jsonl"
    records = source_audit.load_candidates(path)
    assert records
    assert len({record["id"] for record in records}) == len(records)

    required = {
        "id",
        "url",
        "canonical",
        "mirrors",
        "format",
        "tier",
        "enabled",
        "max_nodes",
        "sample_strategy",
        "discovered_at",
    }
    for record in records:
        assert required <= record.keys()
        assert record["enabled"] is False
        assert record["tier"] == 3
        assert record["max_nodes"] is None or record["max_nodes"] > 0
        assert record["sample_strategy"] == "stable_hash"
        assert record["canonical"] == source_audit.canonicalize_url(record["url"])
        assert isinstance(record["mirrors"], list)

    round_one = [record for record in records if record.get("candidate_round") == 1]
    assert len(round_one) == 5
    assert sum(record["max_nodes"] for record in round_one) == 650


def test_candidate_ids_are_not_promoted_into_production_registry() -> None:
    records = source_audit.load_candidates(ROOT / "state" / "candidates.jsonl")
    sources = json.loads((ROOT / "state" / "sources.json").read_text(encoding="utf-8"))
    source_ids = {record.get("id") for record in sources}
    planned_ids = {
        record["id"] for record in records if record.get("candidate_round") in {1, 2}
    }
    assert not (planned_ids & source_ids)
