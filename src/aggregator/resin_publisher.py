"""Resin integration — pour collected nodes into the local resin sticky proxy pool.

Resin is a Docker-hosted sticky proxy pool (localhost:2260) that probes node
health internally (via cloudflare.com/cdn-cgi/trace). This publisher only needs
to push URI lines into a `local` subscription and trigger a refresh; resin does
the liveness probing.

Config (env — repo is public, no hardcoded secrets):
  RESIN_URL            default http://localhost:2260
  RESIN_ADMIN_TOKEN    required (set in .env / GitHub Secrets; no default)

Public API:
  publish_to_resin(name, uris, replace_existing=True) -> summary dict
  publish_from_file(filepath, name)                   -> summary dict
  publish_alive_nodes(name)                            -> summary dict
  run()                                                -> summary dict  (default entry)
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "state"
DB = ROOT / "nodes.db"
LIVE = STATE / "live.jsonl"
GRAY_NODES = STATE / "gray_nodes.jsonl"

DEFAULT_RESIN_URL = "http://localhost:2260"
# RESIN_ADMIN_TOKEN must come from env (no hardcoded default — repo is public).
# Set RESIN_ADMIN_TOKEN in .env (local) or GitHub Secrets (CI).

DEFAULT_SUB_NAME = "free-proxy-aggregator"

# URI schemes resin knows how to parse. Lines that don't start with one of
# these (e.g. the JSON-blob `raw` some vmess rows carry in live.jsonl) are
# silently skipped — resin would drop them anyway.
_PROXY_SCHEMES = (
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "socks://",
    "http://",
    "https://",
)


def _config() -> tuple[str, str]:
    """Return (base_url, admin_token) from env. Token is required (no default
    — repo is public). Returns ("", "") if unset so callers can skip resin."""
    base = os.environ.get("RESIN_URL", DEFAULT_RESIN_URL).rstrip("/")
    token = os.environ.get("RESIN_ADMIN_TOKEN", "")
    return base, token


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _list_subscriptions(base: str, token: str) -> list[dict] | None:
    """GET all subscriptions, distinguishing an empty list from API failure."""
    try:
        r = httpx.get(
            f"{base}/api/v1/subscriptions",
            headers=_headers(token),
            timeout=30.0,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
            return None
        return data.get("items", [])
    except Exception:
        return None


def _delete_subscription(base: str, token: str, sub_id: str) -> bool:
    try:
        r = httpx.delete(
            f"{base}/api/v1/subscriptions/{sub_id}",
            headers=_headers(token),
            timeout=30.0,
        )
        return 200 <= r.status_code < 300 or r.status_code == 204
    except Exception:
        return False


def _get_subscription(base: str, token: str, sub_id: str) -> dict | None:
    """Fetch a single subscription by re-GET-ing the list (no single-item
    endpoint is documented in _GRAY_SPEC.md). Returns the matching item or None."""
    items = _list_subscriptions(base, token)
    if items is None:
        return None
    for it in items:
        if it.get("id") == sub_id:
            return it
    return None


def _is_logical_subscription(item: dict, name: str) -> bool:
    """Candidates are the active replacement for a logical subscription name."""
    current = item.get("name")
    return isinstance(current, str) and (
        current == name or current.startswith(f"{name}--candidate-")
    )


def _count(value: object) -> int:
    """Normalize Resin count fields without trusting response JSON types."""
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def publish_to_resin(
    name: str,
    uris: list[str],
    replace_existing: bool = True,
) -> dict:
    """Create a `local` resin subscription with `uris` as its content, refresh
    it (blocking), and return a summary.

    Replacement is create-then-swap: a uniquely named candidate is created and
    refreshed before any prior logical subscription is removed. A failed create,
    refresh, or parse therefore leaves the prior subscription available.

    Returns:
      {subscription_id, name, node_count, healthy_node_count, uris_pushed,
       replaced_ids:[...], error: Optional[str]}
    """
    base, token = _config()
    uris = [u.strip() for u in uris if u and u.strip()]
    summary: dict = {
        "subscription_id": None,
        "name": name,
        "node_count": 0,
        "healthy_node_count": 0,
        "uris_pushed": len(uris),
        "replaced_ids": [],
    }
    if not uris:
        summary["error"] = "no uris provided"
        return summary
    if not token:
        # No RESIN_ADMIN_TOKEN — skip resin (don't 401). Resin runs on localhost
        # Docker; CI runner can't reach it anyway. Set RESIN_ADMIN_TOKEN in .env
        # to enable local resin publishing.
        summary["error"] = "RESIN_ADMIN_TOKEN not set (skipping resin)"
        return summary

    content = "\n".join(uris)
    subscriptions = _list_subscriptions(base, token)
    if subscriptions is None:
        summary["error"] = "failed to list existing subscriptions"
        return summary
    previous = (
        [it for it in subscriptions if _is_logical_subscription(it, name)]
        if replace_existing
        else []
    )
    create_name = f"{name}--candidate-{uuid.uuid4().hex[:12]}" if previous else name

    # POST new local subscription.
    body = {
        "name": create_name,
        "source_type": "local",
        "content": content,
        "enabled": True,
    }
    try:
        r = httpx.post(
            f"{base}/api/v1/subscriptions",
            headers=_headers(token),
            json=body,
            timeout=60.0,
        )
    except Exception as e:
        summary["error"] = f"POST subscriptions failed: {type(e).__name__}"
        return summary
    if r.status_code not in (200, 201):
        summary["error"] = f"POST subscriptions HTTP {r.status_code}"
        return summary

    try:
        sub = r.json()
    except Exception:
        summary["error"] = "create response was not valid JSON"
        return summary
    if not isinstance(sub, dict):
        summary["error"] = "create response had an invalid shape"
        return summary
    sub_id = sub.get("id")
    summary["subscription_id"] = sub_id
    summary["effective_name"] = create_name
    if not sub_id:
        summary["error"] = "no id in create response"
        return summary

    # POST refresh (blocks until parse/probe round completes per _GRAY_SPEC.md).
    refresh_counts: dict = {}
    try:
        rr = httpx.post(
            f"{base}/api/v1/subscriptions/{sub_id}/actions/refresh",
            headers=_headers(token),
            timeout=180.0,
        )
        if rr.status_code not in (200, 204):
            rolled_back = _delete_subscription(base, token, sub_id)
            summary["subscription_id"] = None
            summary["rolled_back"] = rolled_back
            summary["error"] = f"refresh HTTP {rr.status_code}; prior retained"
            return summary
        if rr.content:
            try:
                payload = rr.json()
                if isinstance(payload, dict):
                    refresh_counts = payload
            except Exception:
                # Some Resin versions return an empty/plain-text success body.
                pass
    except Exception as e:
        rolled_back = _delete_subscription(base, token, sub_id)
        summary["subscription_id"] = None
        summary["rolled_back"] = rolled_back
        summary["error"] = f"refresh failed: {type(e).__name__}; prior retained"
        return summary

    # Resin versions differ: some return counts from refresh, others expose
    # them only in the list endpoint. Prefer the fresh list item when present.
    final = _get_subscription(base, token, sub_id)
    counts = final if isinstance(final, dict) else refresh_counts
    summary["node_count"] = _count(counts.get("node_count"))
    summary["healthy_node_count"] = _count(counts.get("healthy_node_count"))
    if summary["node_count"] <= 0:
        rolled_back = _delete_subscription(base, token, sub_id)
        summary["subscription_id"] = None
        summary["rolled_back"] = rolled_back
        summary["error"] = "candidate parsed zero nodes; prior retained"
        return summary

    deletion_failures: list[str] = []
    for item in previous:
        old_id = item.get("id")
        if not old_id or old_id == sub_id:
            continue
        if _delete_subscription(base, token, old_id):
            summary["replaced_ids"].append(old_id)
        else:
            deletion_failures.append(str(old_id))
    if deletion_failures:
        summary["error"] = (
            "candidate active, but old subscription cleanup failed: "
            + ",".join(deletion_failures)
        )
    return summary


def _extract_uri(line: str) -> str | None:
    """Turn one jsonl line into a proxy URI.

    - pure URI line  -> the line itself
    - JSON line      -> its `raw` field (live.jsonl stores ProxyNode dicts)
    Only returns strings that begin with a known proxy scheme; anything else
    (e.g. a clash-dict JSON blob some vmess rows carry in `raw`) is dropped,
    because resin can't parse it as a node URI anyway.
    """
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            rec = json.loads(line)
        except Exception:
            return None
        raw = rec.get("raw") or rec.get("uri")
        if not isinstance(raw, str):
            return None
        cand = raw.strip()
    else:
        cand = line
    cand = cand.strip()
    if cand.lower().startswith(_PROXY_SCHEMES):
        return cand
    return None


def _extract_enabled_gray_uri(line: str) -> tuple[str | None, str]:
    """Return an explicitly reviewed gray URI and a machine-readable reason.

    Gray records are fail-closed: plain URI lines and JSON without both review
    fields are unreviewed and are never sent to Resin.
    """
    try:
        rec = json.loads(line)
    except Exception:
        return None, "unreviewed"
    if not isinstance(rec, dict):
        return None, "unreviewed"
    if rec.get("enabled") is not True:
        return None, "disabled"
    if rec.get("watermark_suspect") is not False:
        return None, "watermark_or_unreviewed"
    uri = _extract_uri(line)
    return (uri, "enabled") if uri else (None, "invalid_uri")


def publish_from_file(filepath: str | Path, name: str) -> dict:
    """Read a jsonl file (each line a URI or a JSON ProxyNode dict), dedup the
    URIs, and push them into resin under `name`.

    For JSON lines the `raw` field is used (live.jsonl is ProxyNode dicts).
    """
    p = Path(filepath)
    if not p.exists():
        return {
            "subscription_id": None,
            "name": name,
            "node_count": 0,
            "healthy_node_count": 0,
            "uris_pushed": 0,
            "error": f"file not found: {p}",
        }

    seen: set[str] = set()
    uris: list[str] = []
    raw_total = 0
    skipped = 0
    strict_gray = p.resolve() == GRAY_NODES.resolve()
    for line in p.read_text(encoding="utf-8").splitlines():
        uri = _extract_enabled_gray_uri(line)[0] if strict_gray else _extract_uri(line)
        if uri is None:
            if line.strip():
                skipped += 1
            continue
        raw_total += 1
        if uri in seen:
            continue
        seen.add(uri)
        uris.append(uri)

    summary = publish_to_resin(name, uris, replace_existing=True)
    summary["file"] = str(p)
    summary["raw_lines"] = raw_total
    summary["skipped_non_uri"] = skipped
    summary["deduped"] = len(uris)
    return summary


def publish_alive_nodes(name: str = DEFAULT_SUB_NAME) -> dict:
    """Read D1 nodes table, take `alive=1` rows, push their URIs into resin.

    Resin is the ultimate publish layer; the Cloudflare Worker /sub remains a
    fallback. With no alive rows (e.g. verify not yet run — all alive=NULL),
    returns an empty-publish summary rather than crashing.
    """
    if not DB.exists():
        return {
            "subscription_id": None,
            "name": name,
            "node_count": 0,
            "healthy_node_count": 0,
            "uris_pushed": 0,
            "error": f"db not found: {DB}",
        }

    conn = sqlite3.connect(str(DB))
    try:
        rows = conn.execute("SELECT uri FROM nodes WHERE alive=1").fetchall()
    finally:
        conn.close()

    uris: list[str] = []
    seen: set[str] = set()
    for (uri,) in rows:
        if not isinstance(uri, str):
            continue
        cand = uri.strip()
        if not cand.lower().startswith(_PROXY_SCHEMES):
            continue
        if cand in seen:
            continue
        seen.add(cand)
        uris.append(cand)

    summary = publish_to_resin(name, uris, replace_existing=True)
    summary["alive_in_db"] = len(rows)
    summary["deduped"] = len(uris)
    return summary


def _merge_uris(*lists: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for lst in lists:
        for u in lst:
            if u and u not in seen:
                seen.add(u)
                out.append(u)
    return out


def run() -> dict:
    """Default entry: merge state/live.jsonl (alive nodes) + state/gray_nodes.jsonl
    (gray-pipeline nodes), dedup, and pour into the resin subscription
    'free-proxy-aggregator'. Updates state/last-run.json resin stage.
    """
    # live.jsonl: ProxyNode dicts — keep non-dead (alive is None == unverified,
    # kept so the pipeline doesn't block when verify hasn't run, matching
    # emit.filter_alive policy). Take `raw` as the URI.
    live_uris: list[str] = []
    live_total = 0
    live_dead = 0
    if LIVE.exists():
        for line in LIVE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("alive") is False:
                live_dead += 1
                continue
            live_total += 1
            uri = _extract_uri(line)
            if uri:
                live_uris.append(uri)

    # Gray records require an explicit human review decision. Legacy plain URI
    # rows and records missing either review field remain quarantined.
    gray_uris: list[str] = []
    gray_total = 0
    gray_disabled = 0
    gray_watermark_or_unreviewed = 0
    if GRAY_NODES.exists():
        for line in GRAY_NODES.read_text(encoding="utf-8").splitlines():
            uri, reason = _extract_enabled_gray_uri(line)
            if uri:
                gray_uris.append(uri)
                gray_total += 1
            elif reason == "disabled":
                gray_disabled += 1
            else:
                gray_watermark_or_unreviewed += 1

    merged = _merge_uris(live_uris, gray_uris)
    summary = publish_to_resin(DEFAULT_SUB_NAME, merged, replace_existing=True)
    summary["live_nodes"] = live_total
    summary["live_dead_skipped"] = live_dead
    summary["gray_nodes"] = gray_total
    summary["gray_disabled_skipped"] = gray_disabled
    summary["gray_watermark_or_unreviewed_skipped"] = gray_watermark_or_unreviewed
    summary["merged_deduped"] = len(merged)
    return summary


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
