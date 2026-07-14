"""Gray pipeline: Shodan/FOFA/Quake panel recon + open-register harvest.

Stage 10 / A4 (gray). Uses Shodan, FOFA, Quake API to fingerprint V2Board /
Xboard panels, then attempts auto-registration on open-register panels to grab
trial subscribe URLs. Decode the subscribe content (base64 / URI lines) and
append every URI into state/gray_nodes.jsonl (one URI per line).

Design rules (see _GRAY_SPEC.md):
- API keys come from env vars; a missing key logs a skip and continues — no crash.
- No brute force. Panels that require email verification / invite codes are
  skipped (logged) on first non-success response.
- Disposable email, never a real account. email_code is "" (many free panels
  don't verify email).
- httpx with timeout=15, verify=False (self-signed certs are common).
- Rate limit 1 req/s across the three recon APIs.

Run directly:  python src/aggregator/gray_sources.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = ROOT / "config" / "gray_sources.yaml"
STATE_DIR = ROOT / "state"
GRAY_NODES_FILE = STATE_DIR / "gray_nodes.jsonl"
LAST_RUN_FILE = STATE_DIR / "last-run.json"

# URI schemes we harvest from subscribe content.
URI_RE = re.compile(
    r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>\"'#,]+)",
    re.IGNORECASE,
)

# Marker strings to confirm a host is a V2Board/Xboard panel.
PANEL_MARKERS = ("V2Board", "Xboard", "/api/v1/guest/comm/config", "V2board")


# ---------------------------------------------------------------------------
# Config loading + env-var expansion
# ---------------------------------------------------------------------------


def _expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} tokens against os.environ (missing -> '')."""
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
    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return _expand_env(raw)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _log(msg: str) -> None:
    print(f"[gray] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Shodan client
# ---------------------------------------------------------------------------


async def _shodan_search(client: httpx.AsyncClient, cfg: dict) -> list[dict]:
    """Query Shodan for panel fingerprints. Returns list of {host, port, html}."""
    key = cfg.get("shodan_api_key", "").strip()
    if not key:
        _log("SHODAN_API_KEY not set — skipping Shodan.")
        return []
    queries = cfg.get("shodan_queries") or []
    hits: list[dict] = []
    for q in queries:
        try:
            r = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": key, "query": q, "facets": ""},
                timeout=cfg.get("request_timeout_seconds", 15.0),
            )
            if r.status_code == 429:
                _log(f"Shodan rate-limited on query: {q[:60]} — backing off.")
                await asyncio.sleep(2.0)
                continue
            if r.status_code >= 400:
                _log(f"Shodan error {r.status_code} on query: {q[:60]}")
                continue
            data = r.json()
            for m in data.get("matches", []) or []:
                host = m.get("ip_str") or m.get("host")
                port = m.get("port")
                html = (m.get("http") or {}).get("html", "") or ""
                if host:
                    hits.append(
                        {
                            "host": host,
                            "port": port or 443,
                            "html": html,
                            "source": "shodan",
                        }
                    )
        except Exception as e:  # noqa: BLE001
            _log(f"Shodan query failed: {type(e).__name__}: {e}")
        await asyncio.sleep(cfg.get("rate_limit_seconds", 1.0))
    _log(f"Shodan: {len(hits)} raw hits across {len(queries)} queries.")
    return hits


# ---------------------------------------------------------------------------
# FOFA client
# ---------------------------------------------------------------------------


async def _fofa_search(client: httpx.AsyncClient, cfg: dict) -> list[dict]:
    """Query FOFA. query must be base64-encoded. Returns list of {host, port}."""
    email = cfg.get("fofa_email", "").strip()
    key = cfg.get("fofa_key", "").strip()
    if not email or not key:
        _log("FOFA_EMAIL/FOFA_KEY not set — skipping FOFA.")
        return []
    queries = cfg.get("fofa_queries") or []
    hits: list[dict] = []
    for q in queries:
        try:
            q_b64 = base64.b64encode(q.encode("utf-8")).decode("ascii")
            r = await client.get(
                "https://fofa.info/api/v1/search/all",
                params={"email": email, "key": key, "qbase64": q_b64},
                timeout=cfg.get("request_timeout_seconds", 15.0),
            )
            if r.status_code == 429:
                _log("FOFA rate-limited — backing off.")
                await asyncio.sleep(2.0)
                continue
            if r.status_code >= 400:
                _log(f"FOFA error {r.status_code} on query: {q[:60]}")
                continue
            data = r.json()
            for row in data.get("results", []) or []:
                # FOFA returns "host" as "ip:port" or "domain:port"
                host_field = row.get("host", "") if isinstance(row, dict) else ""
                host, port = _split_host_port(host_field, default_port=443)
                if host:
                    hits.append(
                        {"host": host, "port": port, "html": "", "source": "fofa"}
                    )
        except Exception as e:  # noqa: BLE001
            _log(f"FOFA query failed: {type(e).__name__}: {e}")
        await asyncio.sleep(cfg.get("rate_limit_seconds", 1.0))
    _log(f"FOFA: {len(hits)} raw hits across {len(queries)} queries.")
    return hits


# ---------------------------------------------------------------------------
# Quake client
# ---------------------------------------------------------------------------


async def _quake_search(client: httpx.AsyncClient, cfg: dict) -> list[dict]:
    """Query Quake 360. API key in X-QuakeToken header. POST JSON body."""
    key = cfg.get("quake_key", "").strip()
    if not key:
        _log("QUAKE_KEY not set — skipping Quake.")
        return []
    queries = cfg.get("quake_queries") or []
    hits: list[dict] = []
    for q in queries:
        try:
            r = await client.post(
                "https://quake.360.net/api/v3/search/credit",
                headers={"X-QuakeToken": key, "Content-Type": "application/json"},
                json={"query": q, "start": 0, "size": 100},
                timeout=cfg.get("request_timeout_seconds", 15.0),
            )
            if r.status_code == 429:
                _log("Quake rate-limited — backing off.")
                await asyncio.sleep(2.0)
                continue
            if r.status_code >= 400:
                _log(f"Quake error {r.status_code} on query: {q[:60]}")
                continue
            data = r.json()
            for item in data.get("data", []) or []:
                parsed = item.get("parsed") or {}
                service = item.get("service") or {}
                host = parsed.get("ip") or item.get("ip")
                port = parsed.get("port") or service.get("port") or 443
                html = (service.get("http") or {}).get("html", "") or ""
                if host:
                    hits.append(
                        {"host": host, "port": port, "html": html, "source": "quake"}
                    )
        except Exception as e:  # noqa: BLE001
            _log(f"Quake query failed: {type(e).__name__}: {e}")
        await asyncio.sleep(cfg.get("rate_limit_seconds", 1.0))
    _log(f"Quake: {len(hits)} raw hits across {len(queries)} queries.")
    return hits


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_host_port(host_field: str, default_port: int) -> tuple[str, int]:
    """Split 'host:port' (FOFA format). IPv6 in brackets."""
    host_field = (host_field or "").strip()
    if not host_field:
        return "", default_port
    if host_field.startswith("["):
        # [ipv6]:port
        end = host_field.find("]")
        if end != -1:
            host = host_field[1:end]
            rest = host_field[end + 1 :]
            port = (
                int(rest.lstrip(":"))
                if rest.startswith(":") and rest[1:].isdigit()
                else default_port
            )
            return host, port
    parts = host_field.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return host_field, default_port


def _panel_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 2053, 2083, 2087, 2096, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def _looks_like_panel(hit: dict) -> bool:
    html = (hit.get("html") or "").lower()
    return any(m.lower() in html for m in PANEL_MARKERS)


# ---------------------------------------------------------------------------
# Panel register + subscribe harvest (core)
# ---------------------------------------------------------------------------


async def _register_and_grab_sub(
    client: httpx.AsyncClient, cfg: dict, host: str, port: int
) -> str | None:
    """Try to register on a V2Board/Xboard panel and return the subscribe URL.

    Returns the subscribe URL string on success, or None if the panel blocks
    registration (email verification, invite code, captcha, etc.). We never
    brute force — first non-success is a skip.
    """
    pr = cfg.get("panel_register", {}) or {}
    email = pr.get("default_email", "gray@protonmail.com")
    password = pr.get("default_password", "").strip()
    if not password:
        _log(f"  PANEL_PASSWORD not set — cannot register on {host}:{port}.")
        return None
    base = _panel_url(host, port)
    register_path = pr.get("register_path", "/api/v1/passport/auth/register")
    sub_path = pr.get("sub_path", "/api/v1/user/getSubscribe")

    # 1. Register
    reg_url = f"{base}{register_path}"
    try:
        r = await client.post(
            reg_url,
            json={
                "email": email,
                "password": password,
                "email_code": "",
                "invite_code": "",
            },
            timeout=cfg.get("request_timeout_seconds", 15.0),
        )
    except Exception as e:  # noqa: BLE001
        _log(f"  register connect failed {host}:{port}: {type(e).__name__}")
        return None

    if r.status_code >= 500:
        _log(f"  register server error {r.status_code} on {host}:{port} — skip.")
        return None
    if r.status_code >= 400:
        _log(
            f"  register blocked ({r.status_code}) on {host}:{port} — "
            f"likely email-verify/invite — skip. body={_truncate(r.text)}"
        )
        return None

    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        _log(f"  register returned non-JSON on {host}:{port} — skip.")
        return None

    # V2Board/Xboard register returns {data: {...}, code: 0} on success.
    data = body.get("data") if isinstance(body, dict) else None
    token = None
    if isinstance(data, dict):
        token = data.get("token") or (data.get("auth_data") or {}).get("token")
    if not token:
        _log(
            f"  register OK but no token returned on {host}:{port} — "
            f"likely needs email verify — skip. body={_truncate(r.text)}"
        )
        return None

    _log(f"  registered on {host}:{port}, token acquired.")

    # 2. Get subscribe URL
    sub_url = f"{base}{sub_path}"
    try:
        sr = await client.get(
            sub_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=cfg.get("request_timeout_seconds", 15.0),
        )
    except Exception as e:  # noqa: BLE001
        _log(f"  getSubscribe connect failed {host}:{port}: {type(e).__name__}")
        return None

    if sr.status_code >= 400:
        _log(f"  getSubscribe {sr.status_code} on {host}:{port} — skip.")
        return None

    try:
        sbody = sr.json()
    except Exception:  # noqa: BLE001
        _log(f"  getSubscribe non-JSON on {host}:{port} — skip.")
        return None

    sdata = sbody.get("data") if isinstance(sbody, dict) else None
    if not isinstance(sdata, dict):
        _log(f"  getSubscribe no data on {host}:{port} — skip.")
        return None
    subscribe_url = sdata.get("subscribe_url") or sdata.get("token")
    if not subscribe_url:
        _log(f"  getSubscribe no subscribe_url on {host}:{port} — skip.")
        return None
    return subscribe_url


def _truncate(s: str, n: int = 200) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s[:n] + ("…" if len(s) > n else "")


async def _fetch_subscribe_uris(
    client: httpx.AsyncClient, subscribe_url: str
) -> list[str]:
    """Fetch the subscribe URL content and extract URI lines.

    Subscribe content is typically base64-encoded; if so we decode it first.
    Then regex-extract all protocol URIs. We also handle plain-text content.
    """
    try:
        r = await client.get(subscribe_url, timeout=15.0)
    except Exception as e:  # noqa: BLE001
        _log(f"  fetch subscribe content failed: {type(e).__name__}")
        return []
    if r.status_code >= 400:
        _log(f"  subscribe content HTTP {r.status_code}")
        return []
    text = r.text.strip()

    # Try base64 decode (subscription endpoints commonly return base64 blob).
    decoded = None
    try:
        # base64 can have whitespace/newlines; strip then decode.
        candidate = re.sub(r"\s+", "", text)
        if re.fullmatch(r"[A-Za-z0-9+/=]{32,}", candidate):
            decoded = base64.b64decode(candidate, validate=True).decode(
                "utf-8", errors="ignore"
            )
    except Exception:  # noqa: BLE001
        decoded = None

    # Search original + decoded (whichever yields URIs).
    uris: list[str] = []
    for blob in (text, decoded) if decoded else (text,):
        uris = URI_RE.findall(blob or "")
        if uris:
            break
    return uris


# ---------------------------------------------------------------------------
# Dedup panel hosts
# ---------------------------------------------------------------------------


def _dedup_panels(*hit_lists: list[dict]) -> list[dict]:
    """Merge hit lists, dedup by host:port. Prefer hits that look like panels."""
    seen: dict[str, dict] = {}
    for hits in hit_lists:
        for h in hits:
            key = f"{h.get('host')}:{h.get('port')}"
            if key in seen:
                # merge html so panel-marker check sees all evidence
                if h.get("html"):
                    cur = seen[key]
                    cur["html"] = (cur.get("html") or "") + " " + h["html"]
                continue
            seen[key] = dict(h)
    # sort: panel-looking hits first
    return sorted(seen.values(), key=lambda h: not _looks_like_panel(h))


# ---------------------------------------------------------------------------
# State I/O
# ---------------------------------------------------------------------------


def _append_uris(uris: list[str]) -> int:
    """Append URIs to state/gray_nodes.jsonl (one URI per line). Dedup in-file."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if GRAY_NODES_FILE.exists():
        with GRAY_NODES_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                existing.add(line.strip())
    new = [u for u in uris if u and u not in existing]
    # Ensure the file always exists (touch) so downstream G3 resin publisher
    # has a stable path to read even when this run found nothing.
    GRAY_NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with GRAY_NODES_FILE.open("a", encoding="utf-8") as f:
        for u in new:
            f.write(u + "\n")
    return len(new)


def _update_last_run(summary: dict) -> None:
    """Merge a 'gray' stage entry into state/last-run.json (stage 10)."""
    payload: dict = {}
    if LAST_RUN_FILE.exists():
        try:
            payload = json.loads(LAST_RUN_FILE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            payload = {}
    stages = payload.get("stages") if isinstance(payload.get("stages"), dict) else {}
    stages["gray"] = {"ts": int(time.time()), "counts": summary}
    payload["stages"] = stages
    payload["last_gray_run"] = int(time.time())
    LAST_RUN_FILE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


async def _run_async() -> dict:
    cfg = load_config()
    summary = {
        "shodan_hits": 0,
        "fofa_hits": 0,
        "quake_hits": 0,
        "panels_found": 0,
        "panels_registered": 0,
        "nodes_collected": 0,
        "skipped_no_key": [],
    }

    verify = bool(cfg.get("verify_tls", False))
    timeout = cfg.get("request_timeout_seconds", 15.0)
    headers = {"User-Agent": "gray-aggregator/1.0"}

    async with httpx.AsyncClient(
        verify=verify, timeout=timeout, headers=headers, follow_redirects=True
    ) as client:
        shodan_hits = await _shodan_search(client, cfg)
        fofa_hits = await _fofa_search(client, cfg)
        quake_hits = await _quake_search(client, cfg)

        summary["shodan_hits"] = len(shodan_hits)
        summary["fofa_hits"] = len(fofa_hits)
        summary["quake_hits"] = len(quake_hits)

        if not (cfg.get("shodan_api_key", "").strip()):
            summary["skipped_no_key"].append("shodan")
        if not (cfg.get("fofa_email", "").strip() and cfg.get("fofa_key", "").strip()):
            summary["skipped_no_key"].append("fofa")
        if not cfg.get("quake_key", "").strip():
            summary["skipped_no_key"].append("quake")

        panels = _dedup_panels(shodan_hits, fofa_hits, quake_hits)
        summary["panels_found"] = len(panels)
        _log(f"Unique panel candidates: {len(panels)}.")

        max_attempts = int(cfg.get("max_panel_attempts", 50))
        all_uris: list[str] = []
        for p in panels[:max_attempts]:
            host, port = p.get("host"), p.get("port")
            if not host:
                continue
            _log(f"Trying panel {host}:{port} (src={p.get('source')})...")
            sub_url = await _register_and_grab_sub(client, cfg, host, port)
            if not sub_url:
                continue
            summary["panels_registered"] += 1
            _log(f"  subscribe URL: {sub_url}")
            uris = await _fetch_subscribe_uris(client, sub_url)
            if uris:
                _log(f"  harvested {len(uris)} URIs.")
                all_uris.extend(uris)
            else:
                _log(f"  no URIs in subscribe content.")

        # Dedup + append to state file.
        added = _append_uris(all_uris)
        summary["nodes_collected"] = added
        _log(f"Wrote {added} new URIs to {GRAY_NODES_FILE}.")

    _update_last_run(summary)
    return summary


def run() -> dict:
    """Synchronous entry used by CLI / `python gray_sources.py`."""
    return asyncio.run(_run_async())


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
