"""Source and proxy-node deduplication helpers."""

from __future__ import annotations

import hashlib
import json
import re

from .models import ProxyNode


_GITHUB_COM_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/raw/(.+)$", re.IGNORECASE
)


def canonical_url(url: str) -> str:
    """Normalize equivalent GitHub raw-content URLs."""
    if not url:
        return ""
    stripped = url.strip()
    match = _GITHUB_COM_RE.match(stripped)
    if match:
        user, repo, rest = match.groups()
        return f"https://raw.githubusercontent.com/{user}/{repo}/{rest}"
    return stripped.rstrip("/").lower()


def normalize_node(node: ProxyNode) -> str:
    """Stable serialization of connection semantics for content hashing."""
    excluded = {
        "raw",
        "alive",
        "latency_ms",
        "source",
        "content_hash",
        "name",
        "download_speed",
    }
    values = node.model_dump(exclude=excluded, exclude_none=False)
    values["proto"] = (node.proto or "").lower()
    values["host"] = (node.host or "").lower()
    for key in ("sni", "net", "security"):
        value = values.get(key)
        if isinstance(value, str):
            values[key] = value.lower()
    return json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(nodes: list[ProxyNode]) -> str:
    """Hash the normalized node set, independent of input order/duplicates."""
    payload = "\n".join(sorted({normalize_node(node) for node in nodes})).encode(
        "utf-8"
    )
    return hashlib.sha256(payload).hexdigest()


def node_dedup_key(node: ProxyNode) -> str:
    return node.dedup_key()


def dedupe_nodes(nodes: list[ProxyNode]) -> tuple[list[ProxyNode], list[ProxyNode]]:
    """Return unique nodes and duplicates.

    A semantic match is always a duplicate. The raw-URI guard is exact and
    case-sensitive because credentials, paths and fragments can be
    case-sensitive. Empty raw values do not collide with one another.
    """
    seen_keys: set[str] = set()
    seen_raw: set[str] = set()
    unique: list[ProxyNode] = []
    dropped: list[ProxyNode] = []
    for node in nodes:
        key = node_dedup_key(node)
        raw = node.raw.strip()
        raw_seen = bool(raw) and raw in seen_raw
        if key in seen_keys or raw_seen:
            dropped.append(node)
            continue
        seen_keys.add(key)
        if raw:
            seen_raw.add(raw)
        unique.append(node)
    return unique, dropped


def tombstone_source(source: dict, reason: str = "dead") -> dict:
    """Retain a dead source record while disabling future fetches."""
    source["status"] = f"tombstoned:{reason}"
    source["enabled"] = False
    return source
