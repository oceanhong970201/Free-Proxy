"""Stage 18 — A5 Telegram underground market recon (web-preview + honeytrap triage).

Two scrape modes (web_preview default, mtproto reserved):

  **web_preview** (no login): GET https://t.me/s/<channel>?before=<id> — the
  public static mirror. Parse .tgme_widget_message_text via BeautifulSoup.
  Paginate via ?before=<last_message_id>. Regex out proxy URIs
  (vmess/vless/trojan/ss/ssr/tuic/hy2/juicity), net-drive links (mega.nz /
  terabox) and subconverter URLs. If t.me is DNS/GFW-blocked, log + skip —
  no crash.

  **mtproto** (off by default): telethon with api_id / api_hash / session_string.
  Reserved for future work; not implemented here.

Honeytrap triage checklist (see _gray_deep_research.md A5 §7):
  1. watermark token  — per-user unique token / unique node password pattern
  2. provenance       — forward-graph diversity (single channel pushing one
                        host repeatedly == suspect)
  3. hosting domain   — URI host is panel domain vs subconverter / net-drive
  4. TTL and 5. client-coupling are explicitly marked unassessed because they
     require cross-run/runtime evidence.
  6. third-party conversion and 7. local preview are reported as not performed.

Nodes are written to state/gray_nodes.jsonl as JSON lines:
  {raw, uri, channel, tier:"deep-gray", source_channel:"A5",
   enabled:false, watermark_suspect:true|null, triage_reasons:[...],
   triage_unassessed:[...], ts}

Run directly:  python src/aggregator/tg_recon.py
CLI:           python src/aggregator/cli.py tg-recon
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = ROOT / "config" / "tg_channels.yaml"
STATE_DIR = ROOT / "state"
GRAY_NODES_FILE = STATE_DIR / "gray_nodes.jsonl"

# Proxy URI schemes harvested from message text.
URI_RE = re.compile(
    r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>\"'#,]+)",
    re.IGNORECASE,
)

# Net-drive links (collected but not enabled as proxy nodes).
NETDRIVE_RE = re.compile(
    r"https?://(?:[a-z0-9.-]+\.)?(?:mega\.nz|terabox\.com|pan\.baidu\.com|aliyundrive\.net|alipan\.com|115\.com)/[^\s<>\"']+",
    re.IGNORECASE,
)

# Subconverter URLs (third-party conversion backends — flagged for honeytrap
# triage point 6).
SUBCONVERTER_RE = re.compile(
    r"https?://[^\s<>\"']+/(?:sub|link|conversion)\?[^\s<>\"']*target=[^\s<>\"']+",
    re.IGNORECASE,
)

# Message widget container on t.me/s/ static preview.
MESSAGE_TEXT_CLASS = "tgme_widget_message_text"

# Known subconverter / net-drive hosting domains (not panel-owned) — used by
# triage point 3.
_NON_PANEL_HOSTS = (
    "mega.nz",
    "terabox.com",
    "pan.baidu.com",
    "aliyundrive.net",
    "alipan.com",
    "115.com",
)


def _log(msg: str) -> None:
    print(f"[tg-recon] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Config loading + env expansion
# ---------------------------------------------------------------------------


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(
            r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
            lambda m: os.environ.get(m.group(1), ""),
            value,
        )
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return _expand_env(raw)


# ---------------------------------------------------------------------------
# Web-preview scraping
# ---------------------------------------------------------------------------


def _extract_message_texts(html: str) -> list[tuple[str, int | None]]:
    """Return list of (text, message_id) from a t.me/s/ page.

    message_id is taken from the .tgme_widget_message anchor's data-post attr
    (= "<channel>/<id>"); falls back to None if not parseable.
    """
    soup = BeautifulSoup(html, "html.parser")
    out: list[tuple[str, int | None]] = []
    for msg in soup.find_all("div", class_=MESSAGE_TEXT_CLASS):
        text = msg.get_text(" ", strip=True)
        if not text:
            continue
        # walk up to the .tgme_widget_message wrap to find data-post
        mid: int | None = None
        wrap = msg.find_parent("div", class_="tgme_widget_message")
        if wrap is not None:
            post = wrap.get("data-post") or ""
            if "/" in post:
                tail = post.rsplit("/", 1)[-1]
                try:
                    mid = int(tail)
                except ValueError:
                    mid = None
        out.append((text, mid))
    return out


def _earliest_message_id(html: str) -> int | None:
    """Return the smallest message id on the page (for ?before= pagination)."""
    soup = BeautifulSoup(html, "html.parser")
    ids: list[int] = []
    for wrap in soup.find_all("div", class_="tgme_widget_message"):
        post = wrap.get("data-post") or ""
        if "/" in post:
            try:
                ids.append(int(post.rsplit("/", 1)[-1]))
            except ValueError:
                continue
    return min(ids) if ids else None


async def scrape_channel(
    client: httpx.AsyncClient,
    channel: str,
    max_pages: int = 20,
    timeout: float = 15.0,
    rate: float = 1.0,
) -> list[dict]:
    """Scrape one channel via t.me/s/ web preview.

    Returns a list of {uri, channel, msg_id, ts} dicts (one per URI found).
    On DNS / connect failure logs + returns [] (no crash).
    """
    found: list[dict] = []
    before: int | None = None
    for page_idx in range(max_pages):
        url = f"https://t.me/s/{channel}"
        if before is not None:
            url = f"{url}?before={before}"
        try:
            r = await client.get(url, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            _log(
                f"  {channel}: page {page_idx} fetch failed: {type(e).__name__}: {e} — skip"
            )
            break
        if r.status_code >= 400:
            _log(f"  {channel}: page {page_idx} HTTP {r.status_code} — skip")
            break
        html = r.text or ""
        # Detect channels with web preview disabled (empty message list).
        texts = _extract_message_texts(html)
        if not texts:
            _log(
                f"  {channel}: page {page_idx} no messages (preview disabled or end) — stop"
            )
            break

        for text, mid in texts:
            for uri in URI_RE.findall(text):
                found.append(
                    {
                        "uri": uri,
                        "channel": channel,
                        "msg_id": mid,
                        "ts": int(time.time()),
                    }
                )
            # also record net-drive / subconverter links for triage context
            # (not enabled as nodes, but tracked under provenance)
            for _nd in NETDRIVE_RE.findall(text):
                # only used for triage context; not returned as a node
                pass

        earliest = _earliest_message_id(html)
        if earliest is None or (before is not None and earliest >= before):
            # no further pagination possible
            break
        before = earliest
        await asyncio.sleep(rate)

    _log(f"  {channel}: harvested {len(found)} URIs across <= {max_pages} pages")
    return found


# ---------------------------------------------------------------------------
# Honeytrap triage (7 points)
# ---------------------------------------------------------------------------


def _uri_host(uri: str) -> str:
    if uri.lower().startswith("vmess://"):
        payload = uri.split("://", 1)[1]
        try:
            padded = payload + "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="strict")
            value = json.loads(decoded)
            if isinstance(value, dict):
                return str(value.get("add") or value.get("host") or "").lower()
        except Exception:  # noqa: BLE001
            return ""
    try:
        host = urlparse(uri).hostname or ""
    except Exception:  # noqa: BLE001
        host = ""
    return host.lower()


def _looks_like_watermark(uri: str) -> bool:
    """Triage point 1 — watermark token detection.

    Per-user watermarked nodes often carry a unique per-account token in the
    path / query. Heuristics:
      - subscribe_url path /s/<long-hash>
      - query param `token=` / `key=` / `uuid=` with a long opaque value
      - vmess path with a 16+ char opaque segment
    """
    try:
        pu = urlparse(uri)
    except Exception:  # noqa: BLE001
        return False
    path = pu.path or ""
    # /s/<hash> style subscribe path
    if re.search(r"/s/[A-Za-z0-9_-]{16,}", path):
        return True
    # long opaque path segment (>=32) typical of per-user watermarked subs
    if re.search(r"/[A-Za-z0-9_-]{32,}", path):
        return True
    qs = pu.query or ""
    if re.search(r"(?:^|&)(token|key|uuid|tk)=[A-Za-z0-9_-]{16,}", qs, re.I):
        return True
    return False


def _hosting_is_panel(uri: str) -> bool:
    """Triage point 3 — hosting domain: panel-owned vs subconverter / net-drive.

    Returns True if the URI host does NOT look like a known net-drive /
    subconverter domain (i.e. looks panel-owned). Non-panel-hosted cracked
    re-hosts point at subconverter / CF Worker / net-drive.
    """
    host = _uri_host(uri)
    if not host:
        return True  # unknown; don't flag
    for nd in _NON_PANEL_HOSTS:
        if host == nd or host.endswith("." + nd):
            return False
    # crude subconverter heuristic
    if re.search(r"/sub\?|/link\?|/conversion\?", uri, re.I):
        return False
    return True


def honeytrap_triage(
    uri: str,
    channel: str,
    history: list[dict],
    cfg: dict | None = None,
) -> dict:
    """Return an evidence-only triage verdict for a single URI.

    Checks this run did not perform are reported as unassessed instead of being
    mixed into positive evidence or described as completed checks.
    """
    cfg = cfg or {}
    reasons: list[str] = []
    checks: dict[str, str] = {}
    host = _uri_host(uri)

    # 1. watermark token
    if _looks_like_watermark(uri):
        reasons.append("watermark_token: per-user/opaque token pattern in path/query")
        checks["watermark_token"] = "suspect"
    else:
        checks["watermark_token"] = "no_heuristic_match"

    # 2. provenance forward-graph diversity — single channel pushing one host
    push_threshold = int(cfg.get("single_channel_push_threshold", 3))
    same_host_records = [
        r for r in history if host and _uri_host(r.get("uri", "")) == host
    ]
    same_host_same_channel = sum(
        1 for r in same_host_records if r.get("channel") == channel
    )
    host_channels = {str(r.get("channel")) for r in same_host_records}
    if host and same_host_same_channel >= push_threshold and len(host_channels) == 1:
        reasons.append(
            f"provenance: single channel '{channel}' pushed host '{host}' "
            f"{same_host_same_channel}x (>= {push_threshold})"
        )
        checks["provenance"] = "suspect"
    elif host:
        checks["provenance"] = "no_heuristic_match"
    else:
        checks["provenance"] = "not_assessed_host_unavailable"

    # 3. hosting domain
    if not _hosting_is_panel(uri):
        reasons.append(
            f"hosting: host '{host}' looks like subconverter/net-drive "
            "(not panel-owned)"
        )
        checks["hosting"] = "suspect"
    else:
        checks["hosting"] = "no_heuristic_match"

    # TTL needs observations from multiple runs; client coupling needs an
    # actual compatibility test. URI length is not evidence for either.
    checks["ttl"] = "not_assessed_cross_run_history_required"
    checks["client_coupling"] = "not_assessed_runtime_test_required"
    checks["third_party_conversion"] = "not_performed"
    checks["local_preview"] = "not_performed"
    unassessed = [
        "ttl",
        "client_coupling",
        "third_party_conversion",
        "local_preview",
    ]
    suspect = bool(reasons)
    return {
        "suspect": suspect,
        "verdict": "suspect" if suspect else "inconclusive",
        "reasons": reasons,
        "checks": checks,
        "unassessed_checks": unassessed,
        "recommendations": [
            "resample after the configured TTL interval",
            "review parameters locally without a third-party converter",
            "perform client-coupling checks before approval",
        ],
        "complete": False,
    }


# ---------------------------------------------------------------------------
# State I/O
# ---------------------------------------------------------------------------


def _append_gray_nodes(records: list[dict]) -> int:
    """Write A5 nodes to state/gray_nodes.jsonl (JSON lines, resin-compatible).

    Uses `raw` field so resin_publisher._extract_uri can pull the URI; tier is
    "deep-gray", enabled=false, watermark_suspect per triage.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if GRAY_NODES_FILE.exists():
        with GRAY_NODES_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    u = rec.get("raw") or rec.get("uri")
                    if isinstance(u, str):
                        existing.add(u)
                except Exception:  # noqa: BLE001
                    if line.lower().startswith(
                        (
                            "vmess://",
                            "vless://",
                            "trojan://",
                            "ss://",
                            "ssr://",
                            "tuic://",
                            "hysteria2://",
                            "hy2://",
                            "juicity://",
                        )
                    ):
                        existing.add(line)

    ts = int(time.time())
    n = 0
    with GRAY_NODES_FILE.open("a", encoding="utf-8") as f:
        for rec in records:
            u = rec["uri"]
            if u in existing:
                continue
            existing.add(u)
            triage = rec.get("triage", {})
            line_rec = {
                "raw": u,
                "uri": u,
                "channel": rec.get("channel"),
                "tier": "deep-gray",
                "source_channel": "A5",
                "enabled": False,
                # A lack of heuristic evidence is not a clean bill of health:
                # incomplete triage remains null/fail-closed until review.
                "watermark_suspect": True if triage.get("suspect") else None,
                "review_status": "pending",
                "triage_verdict": triage.get("verdict", "inconclusive"),
                "triage_reasons": triage.get("reasons", []),
                "triage_checks": triage.get("checks", {}),
                "triage_unassessed": triage.get("unassessed_checks", []),
                "provenance": {
                    "channel": rec.get("channel"),
                    "msg_id": rec.get("msg_id"),
                    "first_seen_ts": ts,
                },
                "ts": ts,
            }
            f.write(json.dumps(line_rec, ensure_ascii=False) + "\n")
            n += 1
    return n


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


async def _run_async() -> dict:
    cfg = load_config()
    channels = cfg.get("channels") or []
    web_preview = bool(cfg.get("web_preview", True))
    mtproto = bool(cfg.get("mtproto", False))
    max_pages = int(cfg.get("max_pages_per_channel", 20))
    timeout = float(cfg.get("request_timeout_seconds", 15.0))
    rate = float(cfg.get("rate_limit_seconds", 1.0))
    verify = bool(cfg.get("verify_tls", True))

    summary = {
        "mode": (
            "web_preview" if web_preview else ("mtproto" if mtproto else "disabled")
        ),
        "channels": len(channels),
        "uris_harvested": 0,
        "nodes_written": 0,
        "watermark_suspect_count": 0,
        "triage_inconclusive_count": 0,
        "channels_skipped": 0,
    }

    if not channels:
        _log("no channels configured — nothing to do.")
        return summary

    if not web_preview and not mtproto:
        _log("both web_preview and mtproto disabled — nothing to do.")
        return summary

    if mtproto and not web_preview:
        # mtproto-only path is reserved for future telethon integration.
        api_id = cfg.get("telegram_api_id", "").strip()
        api_hash = cfg.get("telegram_api_hash", "").strip()
        session = cfg.get("telegram_session", "").strip()
        if not (api_id and api_hash and session):
            _log(
                "mtproto mode requested but TELEGRAM_API_ID/API_HASH/SESSION "
                "not set — skipping (reserved for future telethon integration)."
            )
            summary["channels_skipped"] = len(channels)
            return summary
        _log("mtproto mode not implemented in this skeleton — skipping.")
        summary["channels_skipped"] = len(channels)
        return summary

    all_records: list[dict] = []
    headers = {"User-Agent": "tg-recon/1.0"}
    async with httpx.AsyncClient(
        verify=verify, timeout=timeout, headers=headers, follow_redirects=True
    ) as client:
        for ch in channels:
            ch = str(ch).strip().lstrip("@")
            if not ch:
                continue
            _log(f"scraping @{ch} (web_preview)...")
            try:
                recs = await scrape_channel(client, ch, max_pages, timeout, rate)
            except Exception as e:  # noqa: BLE001
                _log(f"  @{ch}: scrape crashed: {type(e).__name__}: {e} — skip")
                summary["channels_skipped"] += 1
                continue
            if not recs:
                summary["channels_skipped"] += 1
            all_records.extend(recs)

    summary["uris_harvested"] = len(all_records)

    # triage + write
    triaged: list[dict] = []
    for rec in all_records:
        t = honeytrap_triage(rec["uri"], rec["channel"], all_records, cfg)
        rec["triage"] = t
        if t["suspect"]:
            summary["watermark_suspect_count"] += 1
        else:
            summary["triage_inconclusive_count"] += 1
        triaged.append(rec)

    written = _append_gray_nodes(triaged)
    summary["nodes_written"] = written
    _log(f"done: {summary}")
    return summary


def run() -> dict:
    """Synchronous entry used by CLI / direct invocation."""
    return asyncio.run(_run_async())


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Telegram market recon (A5)")
    ap.add_argument(
        "--mtproto",
        action="store_true",
        help="use mtproto instead of web preview (reserved)",
    )
    args = ap.parse_args()
    if args.mtproto:
        # flip config flag at runtime if caller asks
        cfg_path = CONFIG_FILE
        # minimal: just warn — real mtproto not implemented
        _log("--mtproto requested but mtproto path is reserved / not implemented")
    print(json.dumps(run(), ensure_ascii=False, indent=2))
