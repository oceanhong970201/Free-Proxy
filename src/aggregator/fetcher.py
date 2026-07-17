"""Async source fetcher (Stage 1).

Reads state/sources.json, fetches enabled sources with httpx (20s timeout,
follow redirects), falls back through mirrors on failure. Raw payloads land
in state/staging.jsonl (one JSON line per {source_id, raw, fetched_at}).
Sources.json last_fetch / last_count / status updated in place.

Uses fake-useragent UA. Production runs fail closed: a partial or empty fetch
never replaces the previous staging snapshot. The bundled fixture is available
only when ``ALLOW_FIXTURE_FALLBACK=1`` is set explicitly for local tests.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
SOURCES_FILE = ROOT / "state" / "sources.json"
STAGING_FILE = ROOT / "state" / "staging.jsonl"
FIXTURE = ROOT / "tests" / "fixtures" / "sample-sub.txt"

TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 25 * 1024 * 1024


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
    tmp = SOURCES_FILE.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(sources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tmp.replace(SOURCES_FILE)


def _restore_file(path: Path, previous: bytes | None) -> None:
    current = path.read_bytes() if path.exists() else None
    if current == previous:
        return
    if previous is None:
        path.unlink(missing_ok=True)
        return
    restore = path.with_suffix(path.suffix + ".restore")
    restore.write_bytes(previous)
    restore.replace(path)


def _read_vpnsuper_record(path: Path, source_id: str, expected_count: int) -> dict:
    """Load the harvester hand-off only when it is exactly one valid record."""

    if not path.exists():
        raise ValueError("vpnsuper staging file is missing")
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(lines) != 1:
        raise ValueError(
            f"vpnsuper staging must contain exactly one record, got {len(lines)}"
        )
    try:
        record = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("vpnsuper staging is not valid JSON") from exc
    if not isinstance(record, dict):
        raise ValueError("vpnsuper staging record is not an object")
    if record.get("source_id") != source_id:
        raise ValueError("vpnsuper staging source_id does not match enabled source")
    raw = record.get("raw")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("vpnsuper staging raw payload is empty or invalid")
    fetched_at = record.get("fetched_at")
    if (
        isinstance(fetched_at, bool)
        or not isinstance(fetched_at, int)
        or fetched_at <= 0
    ):
        raise ValueError("vpnsuper staging fetched_at must be a positive integer")
    from .parser import parse_uri

    uri_lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(uri_lines) != expected_count:
        raise ValueError(
            "vpnsuper staging URI count does not match harvester summary: "
            f"{len(uri_lines)} != {expected_count}"
        )
    if any(parse_uri(uri) is None for uri in uri_lines):
        raise ValueError("vpnsuper staging contains an invalid proxy URI")
    return record


async def _fetch_one(
    client: httpx.AsyncClient, src: dict
) -> tuple[dict, str | None, str]:
    """Return (src, raw_text_or_None, status). status in {ok, dead, error}."""
    urls = [src["url"], *(src.get("mirrors") or [])]
    last_err = "unknown error"
    dead_responses = 0
    for url in urls:
        try:
            body = bytearray()
            exceeded = False
            async with client.stream(
                "GET", url, timeout=TIMEOUT, follow_redirects=True
            ) as r:
                if r.status_code == 404 or r.status_code == 410:
                    dead_responses += 1
                    last_err = f"HTTP {r.status_code}"
                    continue
                if r.status_code >= 400:
                    last_err = f"HTTP {r.status_code}"
                    continue
                async for chunk in r.aiter_bytes():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        exceeded = True
                        break
                    body.extend(chunk)
                encoding = r.encoding or "utf-8"
            if exceeded:
                last_err = f"response exceeds {MAX_RESPONSE_BYTES} bytes"
                continue
            text = bytes(body).decode(encoding, errors="replace")
            if text and text.strip():
                return src, text, "ok"
            last_err = "empty body"
        except Exception as e:  # noqa
            last_err = f"{type(e).__name__}: {e}"
            continue
    src["last_error"] = last_err
    return src, None, "dead" if dead_responses == len(urls) else "error"


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

    fetched_records: list[dict] = []
    failed_sources: list[str] = []
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
            try:
                uris = int(vsum.get("uris", 0))
            except (TypeError, ValueError):
                uris = 0
            s["last_fetch"] = now
            s["last_count"] = uris
            if uris:
                # harvest_async wrote state/vpnsuper_staging.jsonl as one
                # {source_id, raw, fetched_at} line — read it back and merge
                # into the main staging stream.
                vp_file = ROOT / "state" / "vpnsuper_staging.jsonl"
                try:
                    record = _read_vpnsuper_record(vp_file, s["id"], uris)
                except ValueError as exc:
                    s["status"] = "error"
                    s["last_error"] = str(exc)
                    summary["errors"] += 1
                    failed_sources.append(s["id"])
                else:
                    fetched_records.append(record)
                    s["status"] = "ok"
                    s.pop("last_error", None)
                    summary["fetched"] += 1
                # mirror into last-run.json stages (harvest_async skips this
                # since we bypassed run()).
                vpnsuper_feed._merge_last_run(vsum)
            else:
                s["status"] = "empty"
                s["last_error"] = "vpnsuper harvester produced no URIs"
                summary["errors"] += 1
                failed_sources.append(s["id"])
        except Exception as e:  # noqa: BLE001
            s["last_fetch"] = now
            s["status"] = "error"
            summary["errors"] += 1
            failed_sources.append(s["id"])
            print(f"[fetch] vpnsuper source {s['id']} failed: {type(e).__name__}: {e}")

    # 2. Standard HTTP sources.
    async with httpx.AsyncClient(headers=headers) as client:
        results = await asyncio.gather(
            *[_fetch_one(client, s) for s in http_sources], return_exceptions=True
        )

    for source, r in zip(http_sources, results, strict=True):
        if isinstance(r, Exception):
            summary["errors"] += 1
            source["status"] = "error"
            source["last_error"] = f"{type(r).__name__}: {r}"
            failed_sources.append(source["id"])
            continue
        src, raw, status = r
        src["last_fetch"] = now
        if status == "ok" and raw is not None:
            src["status"] = "ok"
            src.pop("last_error", None)
            fetched_records.append(
                {"source_id": src["id"], "raw": raw, "fetched_at": now}
            )
            summary["fetched"] += 1
        elif status == "dead":
            src["status"] = "tombstoned"
            summary["dead"] += 1
            failed_sources.append(src["id"])
        else:
            src["status"] = "error"
            summary["errors"] += 1
            failed_sources.append(src["id"])
        # last_count filled later by parser; set None here
        src["last_count"] = src.get("last_count")

    # Fixture fallback is test-only and must be explicitly opted into.
    if (
        summary["fetched"] == 0
        and os.environ.get("ALLOW_FIXTURE_FALLBACK") == "1"
        and FIXTURE.exists()
    ):
        print(f"[fetch] no live sources; loading fixture {FIXTURE}")
        text = FIXTURE.read_text(encoding="utf-8")
        fetched_records.append(
            {"source_id": "fixture-sample", "raw": text, "fetched_at": now}
        )
        summary["fetched"] = 1
        summary["total"] = 1
        summary["errors"] = 0
        summary["dead"] = 0
        failed_sources.clear()
        summary["fallback_fixture"] = True

    if failed_sources or summary["fetched"] != summary["total"]:
        sources_original = SOURCES_FILE.read_bytes() if SOURCES_FILE.exists() else None
        try:
            save_sources(sources)
        except Exception as exc:
            recovery_error = None
            try:
                _restore_file(SOURCES_FILE, sources_original)
            except Exception as restore_exc:  # pragma: no cover - catastrophic I/O
                recovery_error = str(restore_exc)
            summary["source_status_error"] = str(exc)
            if recovery_error:
                summary["source_status_recovery_error"] = recovery_error
        summary["success"] = False
        summary["failed_sources"] = sorted(set(failed_sources))
        summary["error"] = "source snapshot incomplete; previous staging retained"
        return summary

    if not fetched_records:
        summary["success"] = False
        summary["error"] = "no enabled sources produced data"
        return summary

    # Stage both projections before changing either public file. Source status
    # is activated first and restored if staging activation fails.
    tmp = STAGING_FILE.with_suffix(".jsonl.tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as f:
            for rec in fetched_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        summary["success"] = False
        summary["error"] = f"staging snapshot write failed: {exc}"
        return summary

    sources_original = SOURCES_FILE.read_bytes() if SOURCES_FILE.exists() else None
    sources_attempted = False
    try:
        sources_attempted = True
        save_sources(sources)
        tmp.replace(STAGING_FILE)
    except Exception as exc:
        recovery_error = None
        if sources_attempted:
            try:
                _restore_file(SOURCES_FILE, sources_original)
            except Exception as restore_exc:  # pragma: no cover - catastrophic I/O
                recovery_error = str(restore_exc)
        summary["success"] = False
        summary["error"] = f"fetch snapshot activation failed: {exc}" + (
            f"; recovery error: {recovery_error}" if recovery_error else ""
        )
        return summary
    finally:
        tmp.unlink(missing_ok=True)
    summary["success"] = True
    return summary


def run() -> dict:
    return asyncio.run(fetch_all())


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
