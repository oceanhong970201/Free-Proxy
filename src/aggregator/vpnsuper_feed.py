"""VPN Super GitHub-feed harvester — Stage 1 supplemental source.

Continuous-production channel: the `SuperUnlimited/data-backup` repo (branch
v5) serves 438 `dump/<MD5>` files unauthenticated. Each file is:
    [0x10][16-byte IV][AES-256-CBC ciphertext] -> zlib inflate -> JSON

One file is the index (`0ee138d30c80de2e1d516c8d5f06798f`): a {country_code:
hash} map. The rest are per-country server lists: {"servers":[{host,password,
country,...}], "vip_servers":[...]}.

The AES key is the 32-ASCII-byte string `01fb3864e37eb5d4ada3a50a1f1a373e`
(recovered from libnative-legacy.so XOR-0xA5 obfuscation — see
VPNSUPER_REVERSE_REPORT.md). It is used verbatim as an AES-256 key (NOT the
16 bytes the hex decodes to; NOT its MD5).

This module re-derives the node set from the live GitHub feed on every run —
it is the perpetual production mechanism, not a static dump. Output is trojan
URIs (host:443, password from JSON per-node — observed `treeup` / `treeup123`)
written to state/vpnsuper_staging.jsonl as {source_id, raw, fetched_at} lines,
drop-in compatible with the main staging.jsonl the parser consumes.

Run directly:  python src/aggregator/vpnsuper_feed.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = ROOT / "state"
STAGING_FILE = STATE_DIR / "vpnsuper_staging.jsonl"
LAST_RUN_FILE = STATE_DIR / "last-run.json"

# Reverse-engineered constants (static analysis of VPN Super Unlimited Proxy
# v2.28.2 APK; fully recovered, no device/auth needed).
REPO = "SuperUnlimited/data-backup"
BRANCH = "v5"
AES_KEY = b"01fb3864e37eb5d4ada3a50a1f1a373e"  # 32 ASCII bytes -> AES-256
INDEX_HASH = "0ee138d30c80de2e1d516c8d5f06798f"  # country-code -> hash map

RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/dump/"
TREE_API = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"

TIMEOUT = 30.0
# Cap concurrent fetches to stay polite to GitHub raw + avoid CI rate limits.
MAX_CONCURRENCY = 12
# Cap total files we process (438 observed). Index is always fetched first.
MAX_FILES = 500

SOURCE_ID = "vpnsuper-feed"


def _log(msg: str) -> None:
    print(f"[vpnsuper-feed] {msg}", flush=True)


def _ua() -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )


# ---------------------------------------------------------------------------
# GitHub tree enumeration
# ---------------------------------------------------------------------------


def list_dump_files() -> list[str]:
    """List all `dump/<hash>` paths in the repo via the trees API.

    Returns bare hashes (paths minus the `dump/` prefix), sorted. Falls back
    to a known-good static hash list if the API is rate-limited (CI safety).
    """
    headers = {"User-Agent": _ua(), "Accept": "application/vnd.github+json"}
    try:
        r = httpx.get(TREE_API, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            paths = [
                t["path"].split("/", 1)[1]
                for t in data.get("tree", [])
                if str(t.get("path", "")).startswith("dump/")
                and t.get("type") == "blob"
            ]
            if paths:
                return sorted(paths)[:MAX_FILES]
            _log(
                f"tree API 200 but no dump/ paths — full tree: {len(data.get('tree', []))} entries"
            )
        else:
            _log(f"tree API HTTP {r.status_code}: {r.text[:160]}")
    except Exception as e:  # noqa: BLE001
        _log(f"tree API failed: {type(e).__name__}: {e}")
    # Fallback: at minimum the index + a handful of known country hashes from
    # the reverse report (US/FR/DE/SG/GB/CA). Keeps the channel alive even if
    # the trees endpoint is rate-limited on a free CI run.
    _log("falling back to static known-hash set (index + 6 country files).")
    return [
        INDEX_HASH,
        "4937e19cc5e5d5f2bcf50010467567a6",  # US
        "d774bde5371e5021f07d577eb057c45d",  # FR/DE/SG/GB/CA share per report
    ]


# ---------------------------------------------------------------------------
# AES-256-CBC + zlib decrypt
# ---------------------------------------------------------------------------


def decrypt_blob(raw: bytes) -> dict | None:
    """Decrypt + inflate one `dump/<hash>` file -> JSON dict.

    Layout: [1 byte ivLen=0x10][16-byte IV][AES-256-CBC ct] -> zlib -> JSON.
    Key is the 32-ASCII-byte string used verbatim as AES-256 key.
    """
    if not raw or raw[0] != 0x10:
        return None
    iv = raw[1:17]
    ct = raw[17:]
    try:
        from Crypto.Cipher import AES
        import zlib

        pt = AES.new(AES_KEY, AES.MODE_CBC, iv).decrypt(ct)
        # PKCS7 unpad (validate padding bytes) before zlib.
        pad = pt[-1]
        if 1 <= pad <= 16 and all(b == pad for b in pt[-pad:]):
            pt = pt[:-pad]
        json_bytes = zlib.decompress(pt)
        return json.loads(json_bytes)
    except Exception as e:  # noqa: BLE001
        _log(f"  decrypt failed ({len(raw)}B blob): {type(e).__name__}: {e}")
        return None


# ---------------------------------------------------------------------------
# Server-list -> trojan URI
# ---------------------------------------------------------------------------


def _server_to_trojan_uri(s: dict) -> str | None:
    """Build a trojan:// URI from one server-list entry.

    Entry shape: {country, country_name, alias_name, host, password, load, ...}
    Password is per-node (observed `treeup` / `treeup123`) — never hardcode.
    Port defaults to 443 (supx_v1 = Trojan on 443).
    """
    host = str(s.get("host") or "").strip()
    password = str(s.get("password") or "").strip()
    if not host or not password:
        return None
    port = s.get("port") or 443
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 443
    country = str(s.get("country") or "").strip()
    alias = str(s.get("alias_name") or "").strip()
    name = f"vpnsuper-{country}-{alias}-{host}" if country else f"vpnsuper-{host}"
    # trojan://password@host:port?security=tls&sni=host#name
    # sni = host keeps it simple; trojan uses TLS so security=tls is set.
    from urllib.parse import quote, urlencode

    qs = urlencode({"security": "tls", "sni": host}, quote_via=quote)
    frag = quote(name)
    return f"trojan://{password}@{host}:{port}?{qs}#{frag}"


def uris_from_server_doc(doc: dict) -> list[str]:
    """Extract trojan URIs from a decrypted server-list JSON doc."""
    uris: list[str] = []
    seen: set[str] = set()
    for key in ("servers", "vip_servers"):
        arr = doc.get(key)
        if not isinstance(arr, list):
            continue
        for s in arr:
            if not isinstance(s, dict):
                continue
            uri = _server_to_trojan_uri(s)
            if uri and uri not in seen:
                seen.add(uri)
                uris.append(uri)
    return uris


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def _fetch_decrypt_one(
    client: httpx.AsyncClient, h: str
) -> tuple[str, list[str]]:
    """Fetch + decrypt one dump file -> (hash, [trojan uris])."""
    url = RAW_BASE + h
    try:
        r = await client.get(url, timeout=TIMEOUT, follow_redirects=True)
    except Exception as e:  # noqa: BLE001
        _log(f"  fetch {h[:12]} failed: {type(e).__name__}")
        return h, []
    if r.status_code != 200:
        _log(f"  fetch {h[:12]} HTTP {r.status_code}")
        return h, []
    doc = decrypt_blob(r.content)
    if doc is None:
        return h, []
    # Index files (country->hash maps) yield no servers — skip silently.
    uris = uris_from_server_doc(doc)
    return h, uris


async def harvest_async() -> dict:
    """Enumerate tree, fetch+decrypt all dump files, collect trojan URIs."""
    import asyncio

    hashes = list_dump_files()
    # Always ensure the index is fetched first (it defines the country->hash
    # map, but it itself yields no servers — we just confirm it decrypts).
    if INDEX_HASH not in hashes:
        hashes.insert(0, INDEX_HASH)
    _log(
        f"enumerated {len(hashes)} dump files; fetching (concurrency={MAX_CONCURRENCY})."
    )

    headers = {"User-Agent": _ua()}
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def bounded(h: str) -> tuple[str, list[str]]:
        async with sem:
            return await _fetch_decrypt_one(client, h)

    all_uris: list[str] = []
    files_with_servers = 0
    async with httpx.AsyncClient(headers=headers) as client:
        results = await asyncio.gather(*[bounded(h) for h in hashes])

    seen: set[str] = set()
    for h, uris in results:
        if uris:
            files_with_servers += 1
            for u in uris:
                if u not in seen:
                    seen.add(u)
                    all_uris.append(u)

    _log(
        f"harvested {len(all_uris)} unique trojan URIs from "
        f"{files_with_servers}/{len(hashes)} server files."
    )

    # Write staging (drop-in compatible with main staging.jsonl format).
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    if all_uris:
        blob = "\n".join(all_uris)
        with STAGING_FILE.open("w", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {"source_id": SOURCE_ID, "raw": blob, "fetched_at": now},
                    ensure_ascii=False,
                )
                + "\n"
            )
    else:
        STAGING_FILE.write_text("", encoding="utf-8")

    return {
        "files_enumerated": len(hashes),
        "files_with_servers": files_with_servers,
        "uris": len(all_uris),
        "source_id": SOURCE_ID,
    }


def _merge_last_run(summary: dict) -> None:
    """Merge a 'vpnsuper-feed' stage entry into state/last-run.json.

    Shared by both run() (sync entrypoint) and fetcher.fetch_all() (async,
    which bypasses run() and calls harvest_async directly to avoid a nested
    event loop).
    """
    payload: dict = {}
    if LAST_RUN_FILE.exists():
        try:
            payload = json.loads(LAST_RUN_FILE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            payload = {}
    stages = payload.get("stages") if isinstance(payload.get("stages"), dict) else {}
    stages["vpnsuper-feed"] = {"ts": int(time.time()), "counts": summary}
    payload["stages"] = stages
    payload["last_vpnsuper_feed_run"] = int(time.time())
    LAST_RUN_FILE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def run() -> dict:
    """Sync entrypoint. Calls harvest_async via asyncio.run.

    Do NOT call this from inside an already-running event loop (e.g. from
    fetcher.fetch_all, which is itself async) — it would raise "nested event
    loop". In that context, await harvest_async() directly and call
    _merge_last_run() yourself.
    """
    import asyncio

    summary = asyncio.run(harvest_async())
    _log(f"done: {summary}")
    _merge_last_run(summary)
    return summary


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
