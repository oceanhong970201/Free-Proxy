"""Two-layer dedup (Stage 4).

Level 1 (sources layer): canonical URL — github.com/.../raw ↔ raw.githubusercontent.com
Level 2 (node layer):    (host:port:proto:cred:sni) + content_hash
                         content_hash = sha256(sorted normalized node set)

Dead sources (404/410) are tombstoned — record kept, not deleted.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse

from .models import ProxyNode

# canonical URL: map github.com/<u>/<r>/raw/<branch>/<path> -> raw.githubusercontent.com/<u>/<r>/<branch>/<path>
_GITHUB_COM_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/raw/(.+)$", re.IGNORECASE
)


def canonical_url(url: str) -> str:
    """Level 1 canonicalization. Normalizes github raw URLs to raw.githubusercontent.com."""
    if not url:
        return ""
    u = url.strip()
    m = _GITHUB_COM_RE.match(u)
    if m:
        user, repo, rest = m.group(1), m.group(2), m.group(3)
        return f"https://raw.githubusercontent.com/{user}/{repo}/{rest}"
    return u.rstrip("/").lower()


def normalize_node(n: ProxyNode) -> str:
    """Stable serialization of a node for content_hashing (field-sorted, Nones dropped)."""
    d = n.model_dump(exclude_none=True)
    # drop runtime / provenance fields so hash is content-only
    for k in (
        "raw",
        "alive",
        "latency_ms",
        "source",
        "content_hash",
        "name",
        "download_speed",
    ):
        d.pop(k, None)
    # sort keys + items for determinism
    return json.dumps(d, sort_keys=True, ensure_ascii=False)


def content_hash(nodes: list[ProxyNode]) -> str:
    """Level 2: sha256 of the sorted normalized node set — catches mirror subs with identical content."""
    blobs = sorted(normalize_node(n) for n in nodes)
    payload = "\n".join(blobs).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def node_dedup_key(n: ProxyNode) -> str:
    """Per-node dedup key (contract)."""
    return n.dedup_key()


def dedupe_nodes(nodes: list[ProxyNode]) -> tuple[list[ProxyNode], list[ProxyNode]]:
    """Return (unique_nodes, dropped_duplicates). Dedup by dedup_key + raw URI."""
    seen_keys: set[str] = set()
    seen_raw: set[str] = set()
    unique: list[ProxyNode] = []
    dropped: list[ProxyNode] = []
    for n in nodes:
        k = node_dedup_key(n)
        r = n.raw.strip().lower()
        if k in seen_keys or r in seen_raw:
            dropped.append(n)
            continue
        seen_keys.add(k)
        seen_raw.add(r)
        unique.append(n)
    return unique, dropped


def tombstone_source(src: dict, reason: str = "dead") -> dict:
    """Mark a source tombstoned — record kept for Wayback revival."""
    src["status"] = f"tombstoned:{reason}"
    src["enabled"] = False
    return src
