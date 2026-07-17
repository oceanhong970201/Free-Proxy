"""Gray pipeline: passive panel discovery with opt-in approved-target review.

Stage 10 / A4 (gray). Uses Shodan, FOFA, and Quake APIs to discover V2Board /
Xboard panel leads. Registration and subscription review run only for targets
listed in ``panel_register.approved_targets`` while the gate is enabled. Any
harvested URI is stored as a disabled, watermark-suspect JSON record.

Design rules (see _GRAY_SPEC.md):
- API keys come from env vars; a missing key logs a skip and continues — no crash.
- No registration request is sent to a discovery result by default.
- Intelligence API credentials travel only over verified TLS.
- Subscribe destinations and redirects must resolve exclusively to public IPs.
- Rate limit 1 req/s across the three recon APIs.

Run directly:  python src/aggregator/gray_sources.py
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = ROOT / "config" / "gray_sources.yaml"
STATE_DIR = ROOT / "state"
GRAY_NODES_FILE = STATE_DIR / "gray_nodes.jsonl"
LAST_RUN_FILE = STATE_DIR / "last-run.json"
PANEL_LEADS_FILE = STATE_DIR / "gray_panel_leads.jsonl"

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
            # Request exceptions may embed the full URL (including API keys).
            _log(f"Shodan query failed: {type(e).__name__}")
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
                params={
                    "email": email,
                    "key": key,
                    "qbase64": q_b64,
                    "fields": "host,ip,port",
                },
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
                if isinstance(row, dict):
                    host_field = str(row.get("host") or row.get("ip") or "")
                    explicit_port = row.get("port")
                elif isinstance(row, list):
                    host_field = str(row[0]) if row else ""
                    explicit_port = row[2] if len(row) > 2 else None
                else:
                    host_field, explicit_port = "", None
                host, port = _split_host_port(host_field, default_port=443)
                if str(explicit_port or "").isdigit():
                    port = int(explicit_port)
                if host:
                    hits.append(
                        {"host": host, "port": port, "html": "", "source": "fofa"}
                    )
        except Exception as e:  # noqa: BLE001
            _log(f"FOFA query failed: {type(e).__name__}")
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
            _log(f"Quake query failed: {type(e).__name__}")
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
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{rendered_host}:{port}"


def _looks_like_panel(hit: dict) -> bool:
    html = (hit.get("html") or "").lower()
    return any(m.lower() in html for m in PANEL_MARKERS)


def _redact_url(url: str) -> str:
    """Render only an origin; subscription paths and query tokens are secret."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "<invalid>"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme, f"{host}{port}", "/<redacted>", "", ""))
    except Exception:
        return "<redacted-url>"


async def _validate_public_url(url: str) -> tuple[bool, str]:
    """Resolve an HTTP(S) URL and reject every non-global destination."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            return False, "unsupported_scheme"
        if parsed.username is not None or parsed.password is not None:
            return False, "userinfo_forbidden"
        host = parsed.hostname
        if not host:
            return False, "missing_host"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (TypeError, ValueError):
        return False, "malformed_url"

    normalized = host.rstrip(".").lower()
    if not (1 <= port <= 65535):
        return False, "invalid_port"
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return False, "localhost_forbidden"
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        if "." not in normalized:
            return False, "single_label_host_forbidden"
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo,
                normalized,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError:
            return False, "dns_resolution_failed"
        addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for info in infos:
            try:
                addresses.add(ipaddress.ip_address(info[4][0]))
            except (ValueError, IndexError):
                continue
        if not addresses:
            return False, "dns_resolution_failed"
    else:
        addresses = {literal}
    if any(not address.is_global for address in addresses):
        return False, "non_public_destination"
    return True, "ok"


async def _safe_get_public_url(
    client: httpx.AsyncClient,
    url: str,
    timeout: float = 15.0,
    max_redirects: int = 5,
) -> httpx.Response | None:
    """GET a public URL while revalidating DNS and every redirect target."""
    current = url
    initial_scheme = urlsplit(url).scheme
    for _ in range(max_redirects + 1):
        allowed, reason = await _validate_public_url(current)
        if not allowed:
            _log(f"  blocked subscribe URL ({reason}): {_redact_url(current)}")
            return None
        try:
            response = await client.get(
                current, timeout=timeout, follow_redirects=False
            )
        except Exception as exc:  # noqa: BLE001
            _log(f"  fetch subscribe content failed: {type(exc).__name__}")
            return None
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return None
        next_url = urljoin(current, location)
        if initial_scheme == "https" and urlsplit(next_url).scheme != "https":
            _log("  blocked subscribe redirect (TLS downgrade)")
            return None
        current = next_url
    _log("  blocked subscribe URL (redirect limit exceeded)")
    return None


def _approved_panel_targets(cfg: dict) -> list[dict]:
    """Return only targets explicitly listed under an enabled approval gate."""
    panel_cfg = cfg.get("panel_register") or {}
    if not isinstance(panel_cfg, dict) or panel_cfg.get("enabled") is not True:
        return []
    approved = panel_cfg.get("approved_targets") or []
    targets: list[dict] = []
    for item in approved:
        if isinstance(item, str):
            host, port = _split_host_port(item, 443)
            target = {"host": host, "port": port, "source": "approved-config"}
        elif isinstance(item, dict):
            host_field = str(item.get("host") or "")
            host, parsed_port = _split_host_port(host_field, 443)
            port = item.get("port") or parsed_port
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            target = {"host": host, "port": port, "source": "approved-config"}
        else:
            continue
        if target["host"]:
            targets.append(target)
    return _dedup_panels(targets)


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
    allowed, reason = await _validate_public_url(reg_url)
    if not allowed:
        _log(f"  blocked approved panel ({reason}): {_redact_url(reg_url)}")
        return None
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
            "likely email-verify/invite — skip."
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
            "likely needs email verify — skip."
        )
        return None

    _log(f"  registered on {host}:{port}, token acquired.")

    # 2. Get subscribe URL
    sub_url = f"{base}{sub_path}"
    allowed, reason = await _validate_public_url(sub_url)
    if not allowed:
        _log(f"  blocked panel API URL ({reason}): {_redact_url(sub_url)}")
        return None
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


async def _fetch_subscribe_uris(
    client: httpx.AsyncClient, subscribe_url: str
) -> list[str]:
    """Fetch the subscribe URL content and extract URI lines.

    Subscribe content is typically base64-encoded; if so we decode it first.
    Then regex-extract all protocol URIs. We also handle plain-text content.
    """
    r = await _safe_get_public_url(client, subscribe_url, timeout=15.0)
    if r is None:
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
    """Append quarantined JSON records, never implicitly publishable URI rows."""
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
                    raw = rec.get("raw") or rec.get("uri")
                    if isinstance(raw, str):
                        existing.add(raw)
                except Exception:
                    existing.add(line)
    new = [u for u in uris if u and u not in existing]
    # Ensure the file always exists (touch) so downstream G3 resin publisher
    # has a stable path to read even when this run found nothing.
    GRAY_NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with GRAY_NODES_FILE.open("a", encoding="utf-8") as f:
        for u in new:
            record = {
                "raw": u,
                "uri": u,
                "tier": "gray",
                "source_channel": "A4",
                "enabled": False,
                "watermark_suspect": True,
                "review_status": "pending",
                "ts": int(time.time()),
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return len(new)


def _append_panel_leads(panels: list[dict]) -> int:
    """Persist passive discovery results without turning them into targets."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    existing: set[tuple[str, int, str]] = set()
    if PANEL_LEADS_FILE.exists():
        for line in PANEL_LEADS_FILE.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
                existing.add(
                    (str(rec.get("host")), int(rec.get("port")), str(rec.get("source")))
                )
            except Exception:
                continue
    written = 0
    with PANEL_LEADS_FILE.open("a", encoding="utf-8") as handle:
        for panel in panels:
            key = (
                str(panel.get("host") or ""),
                int(panel.get("port") or 443),
                str(panel.get("source") or "unknown"),
            )
            if not key[0] or key in existing:
                continue
            existing.add(key)
            handle.write(
                json.dumps(
                    {
                        "host": key[0],
                        "port": key[1],
                        "source": key[2],
                        "panel_marker": _looks_like_panel(panel),
                        "approved": False,
                        "ts": int(time.time()),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            written += 1
    return written


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
        "leads_written": 0,
        "approved_targets": 0,
        "panels_registered": 0,
        "nodes_collected": 0,
        "skipped_no_key": [],
    }

    timeout = cfg.get("request_timeout_seconds", 15.0)
    headers = {"User-Agent": "gray-aggregator/1.0"}

    async with httpx.AsyncClient(
        verify=True, timeout=timeout, headers=headers, follow_redirects=False
    ) as intelligence_client:
        shodan_hits = await _shodan_search(intelligence_client, cfg)
        fofa_hits = await _fofa_search(intelligence_client, cfg)
        quake_hits = await _quake_search(intelligence_client, cfg)

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
        summary["leads_written"] = _append_panel_leads(panels)

    approved_targets = _approved_panel_targets(cfg)
    summary["approved_targets"] = len(approved_targets)
    if not approved_targets:
        _log("Registration gate closed; passive leads only.")
    else:
        max_attempts = int(cfg.get("max_panel_attempts", 50))
        all_uris: list[str] = []
        panel_verify = bool((cfg.get("panel_register") or {}).get("verify_tls", True))
        async with httpx.AsyncClient(
            verify=panel_verify,
            timeout=timeout,
            headers=headers,
            follow_redirects=False,
        ) as panel_client:
            for p in approved_targets[:max_attempts]:
                host, port = p.get("host"), p.get("port")
                if not host:
                    continue
                _log(f"Trying explicitly approved panel {host}:{port}...")
                sub_url = await _register_and_grab_sub(
                    panel_client, cfg, host, int(port)
                )
                if not sub_url:
                    continue
                summary["panels_registered"] += 1
                _log(f"  subscribe URL: {_redact_url(sub_url)}")
                uris = await _fetch_subscribe_uris(panel_client, sub_url)
                if uris:
                    _log(f"  harvested {len(uris)} quarantined URIs.")
                    all_uris.extend(uris)
                else:
                    _log("  no URIs in subscribe content.")

        # Dedup + append to state file.
        added = _append_uris(all_uris)
        summary["nodes_collected"] = added
        _log(f"Wrote {added} quarantined records to {GRAY_NODES_FILE}.")

    _update_last_run(summary)
    return summary


def run() -> dict:
    """Synchronous entry used by CLI / `python gray_sources.py`."""
    return asyncio.run(_run_async())


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
