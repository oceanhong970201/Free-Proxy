"""Self-owned VPS node pool (Stage 15 — A7, white/legal).

Reads `config/self_nodes.yaml` (manually filled list of the operator's own
legitimately-rented VPS instances running mihomo/xray), rebuilds each entry's
canonical proxy URI via `parser.node_to_uri`, and writes one URI per line to
`state/self_nodes.jsonl`. These are the highest-quality, most-stable nodes and
are merged into the resin subscription "self-owned" by the `publish-self` CLI
command.

Config shape (`config/self_nodes.yaml`):
  nodes:
    - proto: vless          # vless|vmess|trojan|ss|tuic|hysteria2
      host: your-vps.example.com
      port: 443
      uuid: 00000000-0000-0000-0000-000000000000
      sni: your-vps.example.com
      net: ws
      path: /vless
      flow: xtls-rprx-vision
      name: self-vless-01   # optional, used as URI fragment

Public API:
  load_self_nodes() -> list[ProxyNode]
  run()              -> {"nodes": N, "path": str, "uris": [...]}
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

# Bootstrap: allow bare `python src/aggregator/self_nodes.py` (contract) as well
# as `python -m aggregator.self_nodes`. Insert src/ on path before relative
# imports, mirroring cli.py's pattern.
if __package__ is None or "" in __name__.split("."):
    _SRC = Path(__file__).resolve().parents[1]
    import sys

    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))
    from aggregator import parser  # noqa: E402
    from aggregator.models import ProxyNode  # noqa: E402
else:
    from . import parser  # noqa: E402
    from .models import ProxyNode  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "self_nodes.yaml"
STATE = ROOT / "state"
OUT = STATE / "self_nodes.jsonl"

# ProxyNode field names (lowercased) used by node_to_uri. Anything outside
# this set in a YAML entry is ignored (e.g. the human-friendly `tls:` flag
# on vmess, which node_to_uri derives from sni/flow instead).
_NODE_FIELDS = {
    "proto",
    "host",
    "port",
    "uuid",
    "password",
    "method",
    "sni",
    "net",
    "path",
    "host_header",
    "flow",
    "fp",
    "alpn",
    "pbk",
    "sid",
    "name",
}


def _coerce(entry: dict) -> ProxyNode | None:
    """Turn one YAML dict into a ProxyNode with a rebuilt `raw` URI.

    `host` is required and `port` must be a positive int; unknown keys are
    silently dropped so the human-friendly `tls:` flag doesn't cause a
    pydantic validation error (node_to_uri derives TLS from sni/flow).
    """
    host = str(entry.get("host") or "").strip()
    if not host:
        return None
    try:
        port = int(entry.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port <= 0:
        return None
    proto = str(entry.get("proto") or "").strip().lower()
    if not proto:
        return None

    fields: dict = {"proto": proto, "host": host, "port": port}
    for k in _NODE_FIELDS:
        if k in ("proto", "host", "port"):
            continue
        if k in entry:
            v = entry[k]
            # skip empty strings so model defaults (None) apply
            if v is None:
                continue
            if isinstance(v, str) and v.strip() == "":
                continue
            fields[k] = v
    fields["raw"] = ""  # filled by node_to_uri below

    try:
        node = ProxyNode(**fields)
    except Exception:
        return None
    node.raw = parser.node_to_uri(node)
    if not node.raw or "://" not in node.raw:
        return None
    node.source = "self"
    return node


def load_self_nodes() -> list[ProxyNode]:
    """Load config/self_nodes.yaml -> list[ProxyNode] with rebuilt URIs.

    Returns [] if the config is missing or has no `nodes:` key (so a fresh
    checkout with an un-filled seed config publishes an empty pool rather than
    crashing).
    """
    if not CONFIG.exists():
        return []
    try:
        doc = yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    raw_nodes = doc.get("nodes") or []
    if not isinstance(raw_nodes, list):
        return []

    out: list[ProxyNode] = []
    seen: set[str] = set()
    for entry in raw_nodes:
        if not isinstance(entry, dict):
            continue
        node = _coerce(entry)
        if not node:
            continue
        if node.raw in seen:
            continue
        seen.add(node.raw)
        out.append(node)
    return out


def run() -> dict:
    """Default entry: load self nodes, write state/self_nodes.jsonl (one URI
    per line), return {"nodes": N, "path": str, "uris": [...]}.

    Each line is a bare proxy URI (not a JSON ProxyNode dict) so the resin
    publisher's plain-URI branch picks it up directly.
    """
    nodes = load_self_nodes()
    uris = [n.raw for n in nodes if n.raw]

    STATE.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for u in uris:
            f.write(u + "\n")

    return {
        "nodes": len(uris),
        "path": str(OUT),
        "uris": uris,
    }


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
