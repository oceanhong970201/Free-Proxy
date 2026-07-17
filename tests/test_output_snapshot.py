from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from aggregator.parser import parse_clash_yaml, parse_singbox_json, parse_v2ray_base64


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output"


def _assert_semantically_unique(nodes) -> None:
    keys = [node.dedup_key() for node in nodes]
    assert keys
    assert len(keys) == len(set(keys))


def test_published_snapshot_has_no_semantic_duplicates() -> None:
    clash = parse_clash_yaml((OUTPUT / "clash.yaml").read_text(encoding="utf-8"))
    singbox = parse_singbox_json((OUTPUT / "singbox.json").read_text(encoding="utf-8"))
    v2ray = parse_v2ray_base64(
        (OUTPUT / "v2ray-base64.txt").read_text(encoding="utf-8")
    )

    for nodes in (clash, singbox, v2ray):
        _assert_semantically_unique(nodes)

    items = ET.parse(OUTPUT / "feed.xml").getroot().findall("./channel/item")
    guids = [item.findtext("guid") for item in items]
    assert len(items) == len(v2ray)
    assert all(guids)
    assert len(guids) == len(set(guids))
