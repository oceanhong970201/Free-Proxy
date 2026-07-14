"""Async source fetcher (Stage 1).

Reads state/sources.json, fetches enabled sources with httpx (20s timeout,
follow redirects), falls back through mirrors on failure. Raw payloads land
in state/staging.jsonl (one JSON line per {source_id, raw, fetched_at}).
Sources.json last_fetch / last_count / status updated in place.

Uses fake-useragent UA. If every enabled source fails (network-restricted
env), a tests/fixtures/sample-sub.txt fallback is parsed instead so the rest
of the pipeline can still run end-to-end.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
SOURCES_FILE = ROOT / "state" / "sources.json"
STAGING_FILE = ROOT / "state" / "staging.jsonl"
FIXTURE = ROOT / "tests" / "fixtures" / "sample-sub.txt"

TIMEOUT = 20.0


def _ua() -> str:
    try:
        from fake_useragent import UserAgent

        return UserAgent().random
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )


def load_sources() -> list[dict]:
    with SOURCES_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_sources(sources: list[dict]) -> None:
    with SOURCES_FILE.open("w", encoding="utf-8") as f:
        json.dump(sources, f, indent=2, ensure_ascii=False)


async def _fetch_one(
    client: httpx.AsyncClient, src: dict
) -> tuple[dict, str | None, str]:
    """Return (src, raw_text_or_None, status). status in {ok, dead, error}."""
    urls = [src["url"], *(src.get("mirrors") or [])]
    last_err = None
    for url in urls:
        try:
            r = await client.get(url, timeout=TIMEOUT, follow_redirects=True)
            if r.status_code == 404 or r.status_code == 410:
                # tombstone-worthy
                return src, None, "dead"
            if r.status_code >= 400:
                last_err = f"HTTP {r.status_code}"
                continue
            text = r.text
            if text and text.strip():
                return src, text, "ok"
            last_err = "empty body"
        except Exception as e:  # noqa
            last_err = f"{type(e).__name__}: {e}"
            continue
    return src, None, "error"


async def fetch_all() -> dict:
    """Fetch every enabled source. Returns a summary dict.

    Sources with `format == "vpnsuper"` are dispatched to the vpnsuper_feed
    module (GitHub tree enumerate + AES+zlib decrypt) instead of the plain
    HTTP fetch path — that channel produces 438 multi-file decrypted blobs,
    not a single raw URL, so it needs its own harvester.
    """
    sources = load_sources()
    enabled = [s for s in sources if s.get("enabled")]
    headers = {"User-Agent": _ua()}
    summary = {"fetched": 0, "dead": 0, "errors": 0, "total": len(enabled)}

    STAGING_FILE.parent.mkdir(parents=True, exist_ok=True)

    fetched_lines: list[str] = []
    now = int(time.time())

    # 1. vpnsuper-type sources first (own harvester, writes its own staging
    #    line directly; collected here so the main staging.jsonl is unified).
    vpnsuper_sources = [
        s for s in enabled if (s.get("format") or "").lower() == "vpnsuper"
    ]
    http_sources = [s for s in enabled if (s.get("format") or "").lower() != "vpnsuper"]

    for s in vpnsuper_sources:
        try:
            from . import vpnsuper_feed

            # Call the async harvester directly — fetch_all already runs inside
            # asyncio.run(), so calling vpnsuper_feed.run() (which itself calls
            # asyncio.run) would raise "nested event loop". Await harvest_async
            # instead and do the last-run merge inline.
            vsum = await vpnsuper_feed.harvest_async()
            uris = vsum.get("uris", 0)
            s["last_fetch"] = now
            s["last_count"] = uris
            s["status"] = "ok" if uris else "empty"
            if uris:
                # harvest_async wrote state/vpnsuper_staging.jsonl as one
                # {source_id, raw, fetched_at} line — read it back and merge
                # into the main staging stream.
                vp_file = ROOT / "state" / "vpnsuper_staging.jsonl"
                if vp_file.exists():
                    txt = vp_file.read_text(encoding="utf-8").strip()
                    if txt:
                        fetched_lines.append(txt)
                summary["fetched"] += 1
                # mirror into last-run.json stages (harvest_async skips this
                # since we bypassed run()).
                vpnsuper_feed._merge_last_run(vsum)
            else:
                summary["errors"] += 1
        except Exception as e:  # noqa: BLE001
            s["last_fetch"] = now
            s["status"] = "error"
            summary["errors"] += 1
            print(f"[fetch] vpnsuper source {s['id']} failed: {type(e).__name__}: {e}")

    # 2. Standard HTTP sources.
    async with httpx.AsyncClient(headers=headers) as client:
        results = await asyncio.gather(
            *[_fetch_one(client, s) for s in http_sources], return_exceptions=True
        )

    for r in results:
        if isinstance(r, Exception):
            summary["errors"] += 1
            continue
        src, raw, status = r
        src["last_fetch"] = now
        if status == "ok" and raw is not None:
            src["status"] = "ok"
            fetched_lines.append(
                json.dumps(
                    {
                        "source_id": src["id"],
                        "raw": raw,
                        "fetched_at": now,
                    },
                    ensure_ascii=False,
                )
            )
            summary["fetched"] += 1
        elif status == "dead":
            src["status"] = "tombstoned"
            summary["dead"] += 1
        else:
            src["status"] = f"error"
            summary["errors"] += 1
        # last_count filled later by parser; set None here
        src["last_count"] = src.get("last_count")

    # write staging (truncate first)
    with STAGING_FILE.open("w", encoding="utf-8") as f:
        for line in fetched_lines:
            f.write(line + "\n")

    # Fallback: if nothing fetched (offline env), load fixture as a synthetic source
    if summary["fetched"] == 0 and FIXTURE.exists():
        print(f"[fetch] no live sources; loading fixture {FIXTURE}")
        text = FIXTURE.read_text(encoding="utf-8")
        with STAGING_FILE.open("w", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "source_id": "fixture-sample",
                        "raw": text,
                        "fetched_at": now,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
        summary["fetched"] = 1
        summary["fallback_fixture"] = True

    save_sources(sources)
    return summary


def run() -> dict:
    return asyncio.run(fetch_all())


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
