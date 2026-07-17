"""Typer + Rich CLI for the Free-Proxy aggregation pipeline.

  fetch  — sources.json -> state/staging.jsonl
  parse  — staging.jsonl -> dedup -> SQLite nodes table
  verify — clash-speedtest -> backfill state/live.jsonl
  emit   — live.jsonl -> subscriptions + sanitized output/pipeline-status.json
  dashboard — loopback operations UI + isolated node IP checks
  all    — fetch -> parse -> verify -> emit (CI entrypoint)

Updates state/last-run.json {stage, ts, counts} after each run.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

# Bootstrap: allow bare `python src/aggregator/cli.py <cmd>` as the contract specifies,
# not just `python -m aggregator.cli`. Insert src/ on path before relative imports.
if __package__ is None or "" in __name__.split("."):
    _SRC = Path(__file__).resolve().parents[1]
    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))
    from aggregator import fetcher, parser, dedupe, emit  # noqa: E402
    from aggregator import resin_publisher  # noqa: E402
    from aggregator import self_nodes, ct_recon  # noqa: E402
    from aggregator import github_dork  # noqa: E402
    from aggregator import v2board_recon, tg_recon  # noqa: E402
    from aggregator.models import ProxyNode  # noqa: E402
else:
    from . import fetcher, parser, dedupe, emit
    from . import resin_publisher  # noqa: E402
    from . import self_nodes, ct_recon  # noqa: E402
    from . import github_dork  # noqa: E402
    from . import v2board_recon, tg_recon  # noqa: E402
    from .models import ProxyNode

import typer  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "state"
DB = ROOT / "nodes.db"
STAGING = STATE / "staging.jsonl"
LIVE = STATE / "live.jsonl"
LAST_RUN = STATE / "last-run.json"

app = typer.Typer(help="Free-Proxy aggregator CLI.")
console = Console()

VERIFY_PROGRESS_SCHEMA_VERSION = 4
TIER1_BATCH_SIZE = 50
TIER2_BATCH_SIZE = 30


def _now() -> int:
    return int(time.time())


def _read_sources() -> list[dict]:
    return fetcher.load_sources()


def _write_last_run(stage: int, counts: dict, extra: dict | None = None) -> None:
    payload = {"stage": stage, "ts": _now(), "counts": counts}
    if extra:
        payload.update(extra)
    STATE.mkdir(parents=True, exist_ok=True)
    LAST_RUN.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _load_completed_verify_summary() -> tuple[dict | None, str | None]:
    """Load only the immediately preceding successful verification metadata."""

    try:
        document = json.loads(LAST_RUN.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "no valid preceding verify status"
    if not isinstance(document, dict) or document.get("last_stage_cmd") != "verify":
        return None, "emit must immediately follow a successful verify run"
    counts = document.get("counts")
    if not isinstance(counts, dict) or set(counts) != {"verify"}:
        return None, "preceding verify status has an invalid shape"
    summary = counts.get("verify")
    if (
        not isinstance(summary, dict)
        or summary.get("success") is not True
        or summary.get("completed") is not True
    ):
        return None, "preceding verify run was not completed successfully"
    return summary, None


def _init_db() -> sqlite3.Connection:
    DB.parent.mkdir(parents=True, exist_ok=True)
    schema = (ROOT / "infra" / "d1" / "schema.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(str(DB))
    try:
        # Keep existing local databases compatible with the full ProxyNode model.
        # node_json is authoritative; scalar columns remain queryable and mirror D1.
        migrations = {
            "download_speed": "REAL",
            "alter_id": "INTEGER",
            "transport_mode": "TEXT",
            "method": "TEXT",
            "security": "TEXT",
            "tls": "INTEGER",
            "path": "TEXT",
            "host_header": "TEXT",
            "flow": "TEXT",
            "packet_encoding": "TEXT",
            "fp": "TEXT",
            "alpn": "TEXT",
            "pbk": "TEXT",
            "sid": "TEXT",
            "spider_x": "TEXT",
            "utls": "INTEGER",
            "skip_cert_verify": "INTEGER",
            "protocol": "TEXT",
            "protocol_param": "TEXT",
            "obfs": "TEXT",
            "obfs_param": "TEXT",
            "congestion_control": "TEXT",
            "udp_relay_mode": "TEXT",
            "node_json": "TEXT",
            "snapshot_id": "TEXT",
        }
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes'"
        ).fetchone()
        if table_exists:
            existing = {row[1] for row in conn.execute("PRAGMA table_info(nodes)")}
            for column, kind in migrations.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE nodes ADD COLUMN {column} {kind}")
            conn.commit()
        conn.executescript(schema)
        conn.commit()
    except BaseException:
        conn.close()
        raise
    return conn


# ---- core logic (plain callables, used by both CLI commands and `all`) ----
def _fetch_logic() -> dict:
    summary = fetcher.run()
    _write_last_run(1, {"fetch": summary}, extra={"last_stage_cmd": "fetch"})
    return summary


def _parse_logic() -> dict:
    if not STAGING.exists():
        console.print("[red]no staging.jsonl — parse aborted")
        summary = {
            "raw_nodes": 0,
            "unique": 0,
            "duplicates": 0,
            "success": False,
            "error": "no staging.jsonl",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary

    sources = _read_sources()
    staging_lines = [
        line.strip()
        for line in STAGING.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    fixture_mode = False
    if os.environ.get("ALLOW_FIXTURE_FALLBACK") == "1" and len(staging_lines) == 1:
        try:
            fixture_record = json.loads(staging_lines[0])
            fixture_mode = (
                isinstance(fixture_record, dict)
                and fixture_record.get("source_id") == "fixture-sample"
                and isinstance(fixture_record.get("raw"), str)
                and bool(fixture_record["raw"].strip())
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            fixture_mode = False

    snapshot_sources = sources
    if fixture_mode:
        snapshot_sources = [
            {
                "id": "fixture-sample",
                "url": "local://tests/fixtures/sample-sub.txt",
                "format": "raw",
                "enabled": True,
                "tier": 99,
                "status": "fixture",
            }
        ]
    sources_by_id = {
        s["id"]: s
        for s in snapshot_sources
        if isinstance(s, dict) and isinstance(s.get("id"), str) and s["id"]
    }
    enabled_ids = {
        sid for sid, source in sources_by_id.items() if source.get("enabled")
    }
    raw_nodes: list[ProxyNode] = []
    src_counts: dict[str, int] = {}
    staged_sources: set[str] = set()
    invalid_records = 0
    rejected_sources: set[str] = set()
    duplicate_sources: set[str] = set()

    for line_number, line in enumerate(staging_lines, 1):
        try:
            rec = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            invalid_records += 1
            continue
        if not isinstance(rec, dict):
            invalid_records += 1
            continue
        sid = rec.get("source_id")
        text = rec.get("raw")
        if (
            not isinstance(sid, str)
            or not sid
            or not isinstance(text, str)
            or not text.strip()
        ):
            invalid_records += 1
            continue
        if sid not in enabled_ids:
            rejected_sources.add(sid)
            continue
        if sid in staged_sources:
            duplicate_sources.add(sid)
            continue
        staged_sources.add(sid)
        src_fmt = sources_by_id[sid].get("format")
        if not isinstance(src_fmt, str) or not src_fmt:
            invalid_records += 1
            continue
        try:
            nodes = parser.parse_raw(src_fmt, text)
        except (TypeError, ValueError):
            invalid_records += 1
            continue
        for n in nodes:
            n.source = sid
        raw_nodes.extend(nodes)
        src_counts[sid] = src_counts.get(sid, 0) + len(nodes)

    missing_sources = sorted(enabled_ids - staged_sources)
    empty_sources = sorted(sid for sid in enabled_ids if src_counts.get(sid, 0) == 0)
    if (
        invalid_records
        or missing_sources
        or empty_sources
        or rejected_sources
        or duplicate_sources
    ):
        summary = {
            "raw_nodes": len(raw_nodes),
            "unique": 0,
            "duplicates": 0,
            "by_source": src_counts,
            "success": False,
            "invalid_records": invalid_records,
            "missing_sources": missing_sources,
            "empty_sources": empty_sources,
            "rejected_sources": sorted(rejected_sources),
            "duplicate_sources": sorted(duplicate_sources),
            "error": "staging snapshot failed validation; prior DB/live snapshot retained",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary

    unique, dropped = dedupe.dedupe_nodes(raw_nodes)
    chash = dedupe.content_hash(unique)
    if not unique:
        summary = {
            "raw_nodes": len(raw_nodes),
            "unique": 0,
            "duplicates": len(dropped),
            "by_source": src_counts,
            "success": False,
            "error": "parser produced no nodes; prior DB/live snapshot retained",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary

    LIVE.parent.mkdir(parents=True, exist_ok=True)
    live_tmp = LIVE.with_suffix(".jsonl.tmp")
    with live_tmp.open("w", encoding="utf-8", newline="\n") as f:
        for n in unique:
            n.alive = None
            n.latency_ms = None
            n.download_speed = None
            f.write(json.dumps(n.model_dump(mode="json"), ensure_ascii=False) + "\n")

    conn = _init_db()
    now = _now()
    sources_path = fetcher.SOURCES_FILE
    live_original = LIVE.read_bytes() if LIVE.exists() else None
    sources_original = sources_path.read_bytes() if sources_path.exists() else None
    live_attempted = False
    sources_attempted = False

    def restore_file(path: Path, previous: bytes | None) -> None:
        current = path.read_bytes() if path.exists() else None
        if current == previous:
            return
        if previous is None:
            path.unlink(missing_ok=True)
            return
        restore = path.with_suffix(path.suffix + ".restore")
        restore.write_bytes(previous)
        restore.replace(path)

    try:
        previous_first_seen = dict(
            conn.execute(
                "SELECT uri, first_seen FROM nodes WHERE first_seen IS NOT NULL"
            )
        )
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM nodes")
        for s in snapshot_sources:
            s["last_count"] = src_counts.get(s["id"], 0)
            conn.execute(
                """INSERT INTO sources(id,url,format,enabled,tier,last_fetch,last_count,status)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     url=excluded.url, format=excluded.format, enabled=excluded.enabled,
                     tier=excluded.tier, last_fetch=excluded.last_fetch,
                     last_count=excluded.last_count, status=excluded.status""",
                (
                    s["id"],
                    s["url"],
                    s["format"],
                    1 if s.get("enabled") else 0,
                    s.get("tier", 3),
                    s.get("last_fetch"),
                    s["last_count"],
                    s.get("status", "unknown"),
                ),
            )
        for n in unique:
            node_hash = hashlib.sha256(
                dedupe.normalize_node(n).encode("utf-8")
            ).hexdigest()
            scalar_alpn = n.alpn if isinstance(n.alpn, str) else json.dumps(n.alpn)
            conn.execute(
                """INSERT INTO nodes(
                     uri,proto,host,port,uuid,alter_id,password,method,sni,net,
                     transport_mode,
                     security,tls,path,host_header,flow,packet_encoding,fp,alpn,
                     pbk,sid,spider_x,utls,
                     skip_cert_verify,protocol,protocol_param,obfs,obfs_param,
                     congestion_control,udp_relay_mode,
                     country,latency_ms,download_speed,alive,source,first_seen,
                     last_checked,content_hash,node_json,snapshot_id)
                   VALUES(
                     :uri,:proto,:host,:port,:uuid,:alter_id,:password,:method,
                     :sni,:net,:transport_mode,:security,:tls,:path,:host_header,
                     :flow,:packet_encoding,:fp,:alpn,:pbk,:sid,:spider_x,:utls,
                     :skip_cert_verify,:protocol,:protocol_param,
                     :obfs,:obfs_param,:congestion_control,:udp_relay_mode,
                     NULL,NULL,NULL,NULL,:source,:first_seen,:last_checked,
                     :content_hash,:node_json,NULL)""",
                {
                    "uri": n.raw,
                    "proto": n.proto,
                    "host": n.host,
                    "port": n.port,
                    "uuid": n.uuid,
                    "alter_id": n.alter_id,
                    "password": n.password,
                    "method": n.method,
                    "sni": n.sni,
                    "net": n.net,
                    "transport_mode": n.transport_mode,
                    "security": n.security,
                    "tls": None if n.tls is None else int(bool(n.tls)),
                    "path": n.path,
                    "host_header": n.host_header,
                    "flow": n.flow,
                    "packet_encoding": n.packet_encoding,
                    "fp": n.fp,
                    "alpn": scalar_alpn,
                    "pbk": n.pbk,
                    "sid": n.sid,
                    "spider_x": n.spider_x,
                    "utls": None if n.utls is None else int(bool(n.utls)),
                    "skip_cert_verify": (
                        None if n.skip_cert_verify is None else int(n.skip_cert_verify)
                    ),
                    "protocol": n.protocol,
                    "protocol_param": n.protocol_param,
                    "obfs": n.obfs,
                    "obfs_param": n.obfs_param,
                    "congestion_control": n.congestion_control,
                    "udp_relay_mode": n.udp_relay_mode,
                    "source": n.source,
                    "first_seen": previous_first_seen.get(n.raw) or now,
                    "last_checked": now,
                    "content_hash": node_hash,
                    "node_json": json.dumps(
                        n.model_dump(mode="json"), ensure_ascii=False
                    ),
                },
            )
        # Activate both file projections while SQLite can still roll back.
        # If either file or the final commit fails, restore every prior view.
        if not fixture_mode:
            sources_attempted = True
            fetcher.save_sources(sources)
        live_attempted = True
        live_tmp.replace(LIVE)
        conn.commit()
    except Exception as e:
        conn.rollback()
        live_tmp.unlink(missing_ok=True)
        recovery_errors: list[str] = []
        if live_attempted:
            try:
                restore_file(LIVE, live_original)
            except Exception as recovery_exc:  # pragma: no cover - catastrophic I/O
                recovery_errors.append(f"live.jsonl: {recovery_exc}")
        if sources_attempted:
            try:
                restore_file(sources_path, sources_original)
            except Exception as recovery_exc:  # pragma: no cover - catastrophic I/O
                recovery_errors.append(f"sources.json: {recovery_exc}")
        recovery_note = (
            f"; recovery errors: {'; '.join(recovery_errors)}"
            if recovery_errors
            else ""
        )
        summary = {
            "raw_nodes": len(raw_nodes),
            "unique": len(unique),
            "duplicates": len(dropped),
            "success": False,
            "error": f"snapshot activation failed: {e}{recovery_note}",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary
    finally:
        conn.close()

    summary = {
        "raw_nodes": len(raw_nodes),
        "unique": len(unique),
        "duplicates": len(dropped),
        "by_source": src_counts,
        "content_hash": chash,
        "success": True,
    }
    _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
    return summary


def _load_quality() -> dict:
    """Load config/quality.yaml (two-tier verify + publish params)."""
    import yaml as _yaml

    qpath = ROOT / "config" / "quality.yaml"
    if not qpath.exists():
        return {}
    return _yaml.safe_load(qpath.read_text(encoding="utf-8")) or {}


def _find_speedtest_binary() -> str | None:
    """Locate clash-speedtest without relying on a developer-specific home path."""
    override = os.environ.get("CLASH_SPEEDTEST_BIN", "").strip()
    if override and Path(override).is_file():
        return override

    binary = shutil.which("clash-speedtest")
    if binary:
        return binary

    executable = "clash-speedtest.exe" if os.name == "nt" else "clash-speedtest"
    go_path = Path(os.environ.get("GOPATH", "").strip() or (Path.home() / "go"))
    candidate = go_path / "bin" / executable
    if candidate.is_file():
        return str(candidate)
    return None


def _parse_speed(value: str) -> float | None:
    """Parse clash-speedtest download-speed column value -> MB/s float.

    Output format observed (2026-07 probe):
      '754.40KB/s' -> 0.754 MB/s
      '5.00MB/s'   -> 5.0 MB/s
      'N/A'        -> None
    """
    if not value:
        return None
    v = value.strip()
    if v.lower() in ("n/a", "na", "", "-"):
        return None
    v_low = v.lower()
    try:
        if "kb/s" in v_low:
            return round(float(v_low.replace("kb/s", "").strip()) / 1024.0, 4)
        if "mb/s" in v_low:
            return round(float(v_low.replace("mb/s", "").strip()), 4)
        if "gb/s" in v_low:
            return round(float(v_low.replace("gb/s", "").strip()) * 1024.0, 4)
        return float(v)
    except ValueError:
        return None


def _parse_latency(value: str) -> int | None:
    """Parse clash-speedtest latency column -> ms int. '454ms' -> 454, 'N/A' -> None."""
    if not value:
        return None
    v = value.strip().lower().replace("ms", "").strip()
    if v in ("n/a", "na", "", "-"):
        return None
    try:
        return int(float(v))
    except ValueError:
        return None


def _verify_logic(max_runtime: int | None = None) -> dict:
    """Verify each full proxy configuration without sharing results by endpoint."""
    import yaml as _yaml

    q = _load_quality()
    max_latency_ms = int(q.get("max_latency_ms", 1000))
    min_dl_mbps = float(q.get("min_download_speed_mbps", 5))
    t1_conc = int(q.get("tier1_concurrent", 50))
    t2_conc = int(q.get("tier2_concurrent", 10))
    dl_size = int(q.get("download_size_bytes", 10485760))
    probe_timeout_seconds = max(1, int(q.get("probe_timeout_seconds", 5)))
    process_timeout_seconds = max(
        probe_timeout_seconds + 5,
        int(q.get("verifier_process_timeout_seconds", 30)),
    )
    start_t = time.time()
    progress_file = STATE / "verify-progress.json"

    conn = _init_db()
    rows = conn.execute(
        """SELECT uri,node_json,source,alive,latency_ms,download_speed
           FROM nodes ORDER BY id"""
    ).fetchall()
    conn.close()

    nodes: list[ProxyNode] = []
    for row in rows:
        (
            uri,
            node_json,
            source,
            alive,
            lat,
            dl,
        ) = row
        try:
            if node_json:
                data = json.loads(node_json)
                if not isinstance(data, dict):
                    raise TypeError("node_json is not an object")
                data.update({"raw": uri, "source": source})
                node = ProxyNode(**data)
            else:
                node = parser.parse_uri(uri)
                if node is None:
                    raise ValueError("legacy URI cannot be parsed")
                node.source = source
            parser.validate_node_raw(node)
        except Exception as exc:
            summary = {
                "completed": False,
                "success": False,
                "error": f"invalid database node at row {len(nodes) + 1}: {exc}",
            }
            _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
            return summary
        node.alive = bool(alive) if alive is not None else None
        node.latency_ms = lat
        node.download_speed = dl
        nodes.append(node)

    if not nodes:
        summary = {"completed": False, "success": False, "error": "no nodes to verify"}
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary

    binary = _find_speedtest_binary()
    if not binary:
        summary = {
            "completed": False,
            "success": False,
            "unverified": len(nodes),
            "error": "clash-speedtest not found",
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary
    console.print(f"[green]clash-speedtest found at {binary}")

    verifier_nodes = [node for node in nodes if not emit.clash_skip_reason(node)]
    unsupported_nodes = [node for node in nodes if emit.clash_skip_reason(node)]
    unsupported_uris = {node.raw for node in unsupported_nodes}
    if not verifier_nodes:
        summary = {
            "completed": False,
            "success": False,
            "unsupported_for_verifier": len(unsupported_nodes),
            "error": "no nodes are representable by the pinned Clash verifier",
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary

    clash = emit.emit_clash(verifier_nodes)
    all_proxies = clash.get("proxies", [])
    if len(all_proxies) != len(verifier_nodes):
        summary = {
            "completed": False,
            "success": False,
            "error": (
                "Clash conversion count mismatch: "
                f"{len(all_proxies)} != {len(verifier_nodes)}"
            ),
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary

    name_to_uri = {
        p["name"]: n.raw for p, n in zip(all_proxies, verifier_nodes, strict=True)
    }
    if len(name_to_uri) != len(verifier_nodes):
        summary = {
            "completed": False,
            "success": False,
            "error": "duplicate Clash names",
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary

    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "progress_schema": VERIFY_PROGRESS_SCHEMA_VERSION,
                "verifier_contract": "clash-speedtest-isolated-v4",
                "quality": q,
                "tier1_batch_size": TIER1_BATCH_SIZE,
                "tier2_batch_size": TIER2_BATCH_SIZE,
                "connections": [
                    {"uri": n.raw, "proxy": p}
                    for p, n in zip(all_proxies, verifier_nodes, strict=True)
                ],
                "unsupported": sorted(unsupported_uris),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    tier1_alive: dict[str, int] = {}
    tier1_tested: set[str] = set()
    tier2_speeds: dict[str, float] = {}
    tier2_tested: set[str] = set()
    reachable: set[str] = set()
    resume_idx = 0
    resumed = False

    try:
        if progress_file.exists():
            saved = json.loads(progress_file.read_text(encoding="utf-8"))
            if (
                saved.get("schema_version") == VERIFY_PROGRESS_SCHEMA_VERSION
                and saved.get("fingerprint") == fingerprint
            ):
                tier1_alive = {
                    str(k): int(v) for k, v in saved.get("tier1_alive", {}).items()
                }
                tier1_tested = set(saved.get("tier1_tested", []))
                tier2_speeds = {
                    str(k): float(v) for k, v in saved.get("tier2_speeds", {}).items()
                }
                tier2_tested = set(saved.get("tier2_tested", []))
                reachable = set(saved.get("reachable", []))
                resume_idx = int(saved.get("tier1_idx", 0))
                resumed = True
    except Exception as e:
        console.print(f"[yellow]discarding invalid verify progress: {e}")

    def save_progress(t1_idx: int) -> None:
        tmp = progress_file.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(
                {
                    "schema_version": VERIFY_PROGRESS_SCHEMA_VERSION,
                    "fingerprint": fingerprint,
                    "tier1_idx": t1_idx,
                    "tier1_alive": tier1_alive,
                    "tier1_tested": sorted(tier1_tested),
                    "tier2_speeds": tier2_speeds,
                    "tier2_tested": sorted(tier2_tested),
                    "reachable": sorted(reachable),
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        tmp.replace(progress_file)

    if not resumed:
        from aggregator import tcp_prefilter

        for n in nodes:
            n.alive = None
            n.latency_ms = None
            n.download_speed = None
        console.print("[cyan]running TCP pre-filter...")
        reachable = tcp_prefilter.run(all_proxies)
        if not reachable:
            summary = {
                "completed": False,
                "success": False,
                "unverified": len(nodes),
                "error": "TCP pre-filter returned no reachable endpoints",
            }
            _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
            return summary
        save_progress(0)

    pairs = [
        (p, n)
        for p, n in zip(all_proxies, verifier_nodes, strict=True)
        if f"{p.get('server')}:{p.get('port')}" in reachable
    ]
    filtered_proxies = [p for p, _ in pairs]
    console.print(f"[cyan]TCP pre-filter: {len(pairs)}/{len(nodes)} reachable")

    def run_isolated(proxy: dict, tier: int, sequence: int) -> dict:
        """Run one proxy per verifier process so a stuck core cannot poison a wave."""
        path = STATE / f"_verify_t{tier}_{sequence}_{uuid.uuid4().hex}.yaml"
        try:
            with path.open("w", encoding="utf-8") as fh:
                _yaml.safe_dump(
                    {"proxies": [proxy]}, fh, allow_unicode=True, sort_keys=False
                )
            args = [
                binary,
                "-c",
                str(path),
                "-rename=false",
                "-f",
                ".+",
                "-concurrent",
                "1",
                "-timeout",
                f"{probe_timeout_seconds}s",
            ]
            if tier == 1:
                args.append("-fast")
            else:
                args.extend(
                    [
                        "-speed-mode",
                        "download",
                        "-download-size",
                        str(dl_size),
                        "-max-latency",
                        f"{max_latency_ms}ms",
                        "-min-download-speed",
                        str(min_dl_mbps),
                    ]
                )
            try:
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=process_timeout_seconds,
                    encoding="utf-8",
                    errors="replace",
                )
            except subprocess.TimeoutExpired:
                return {"kind": "isolated_failure", "reason": "timed out"}
            except Exception as exc:
                return {"kind": "fatal", "reason": str(exc)}
        finally:
            path.unlink(missing_ok=True)

        if proc.returncode != 0:
            return {
                "kind": "isolated_failure",
                "reason": f"exit {proc.returncode}: {proc.stderr[-300:]}",
            }

        expected_uri = name_to_uri[proxy["name"]]
        recognized = 0
        unknown_names = 0
        metric: int | float | None = None
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            required = 4 if tier == 1 else 7
            if len(parts) < required or not parts[0].strip().endswith("."):
                continue
            uri = name_to_uri.get(parts[1].strip())
            if uri != expected_uri:
                unknown_names += 1
                continue
            recognized += 1
            metric = _parse_latency(parts[3]) if tier == 1 else _parse_speed(parts[6])
        if unknown_names or recognized != 1:
            return {
                "kind": "contract",
                "reason": (
                    f"unknown_names={unknown_names}, recognized_rows={recognized}"
                ),
            }
        return {"kind": "ok", "metric": metric}

    error: str | None = None
    timed_out = False
    isolated_t1_failures = 0
    isolated_t2_failures = 0
    t1_complete = False
    batch1 = TIER1_BATCH_SIZE
    for i in range(resume_idx, len(filtered_proxies), batch1):
        if max_runtime and time.time() - start_t >= max_runtime:
            timed_out = True
            save_progress(i)
            break
        chunk = filtered_proxies[i : i + batch1]
        workers = max(1, min(t1_conc, len(chunk)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(
                executor.map(
                    lambda item: run_isolated(item[1], 1, i + item[0]),
                    enumerate(chunk),
                )
            )
        contract_error = next(
            (result for result in results if result["kind"] in {"fatal", "contract"}),
            None,
        )
        if contract_error:
            error = f"Tier-1 verifier error at wave {i}: {contract_error['reason']}"
            save_progress(i)
            break
        successful = sum(result["kind"] == "ok" for result in results)
        failed = len(results) - successful
        if failed and not successful:
            error = f"Tier-1 wave {i} had no successful verifier process"
            save_progress(i)
            break

        expected = {name_to_uri[p["name"]] for p in chunk}
        tier1_tested.difference_update(expected)
        for uri in expected:
            tier1_alive.pop(uri, None)
        tier1_tested.update(expected)
        for proxy, result in zip(chunk, results, strict=True):
            if result["kind"] != "ok":
                continue
            latency = result["metric"]
            if isinstance(latency, int) and latency < max_latency_ms:
                tier1_alive[name_to_uri[proxy["name"]]] = latency
        isolated_t1_failures += failed
        resume_idx = i + len(chunk)
        save_progress(resume_idx)
    else:
        t1_complete = True
        save_progress(len(filtered_proxies))

    # TCP-unreachable endpoints are known dead; reachable but untested remain None.
    for n in nodes:
        if n.raw in unsupported_uris:
            n.alive = False
            n.latency_ms = None
            n.download_speed = None
            continue
        hp = f"{n.host}:{n.port}"
        if hp not in reachable:
            n.alive = False
            n.latency_ms = None
            n.download_speed = None
        elif n.raw in tier1_tested:
            n.alive = n.raw in tier1_alive
            n.latency_ms = tier1_alive.get(n.raw)
            n.download_speed = None
        else:
            n.alive = None
            n.latency_ms = None
            n.download_speed = None

    if t1_complete and not tier1_alive and len(filtered_proxies) > 100:
        error = "Tier-1 returned zero alive nodes for a large snapshot"
        t1_complete = False

    alive_proxies = [p for p in all_proxies if name_to_uri[p["name"]] in tier1_alive]
    t2_complete = not alive_proxies
    if t1_complete and not error and alive_proxies:
        for i in range(0, len(alive_proxies), TIER2_BATCH_SIZE):
            if max_runtime and time.time() - start_t >= max_runtime:
                timed_out = True
                break
            batch = alive_proxies[i : i + TIER2_BATCH_SIZE]
            chunk = [p for p in batch if name_to_uri[p["name"]] not in tier2_tested]
            if not chunk:
                continue
            workers = max(1, min(t2_conc, len(chunk)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                results = list(
                    executor.map(
                        lambda item: run_isolated(item[1], 2, i + item[0]),
                        enumerate(chunk),
                    )
                )
            contract_error = next(
                (
                    result
                    for result in results
                    if result["kind"] in {"fatal", "contract"}
                ),
                None,
            )
            if contract_error:
                error = f"Tier-2 verifier error at wave {i}: {contract_error['reason']}"
                break
            successful = sum(result["kind"] == "ok" for result in results)
            failed = len(results) - successful
            if failed and not successful:
                error = f"Tier-2 wave {i} had no successful verifier process"
                break

            expected = {name_to_uri[p["name"]] for p in chunk}
            tier2_tested.difference_update(expected)
            for uri in expected:
                tier2_speeds.pop(uri, None)
            tier2_tested.update(expected)
            for proxy, result in zip(chunk, results, strict=True):
                if result["kind"] != "ok":
                    continue
                speed = result["metric"]
                if isinstance(speed, (int, float)) and speed >= min_dl_mbps:
                    tier2_speeds[name_to_uri[proxy["name"]]] = float(speed)
            isolated_t2_failures += failed
            save_progress(len(filtered_proxies))
        else:
            t2_complete = True

    for n in nodes:
        if n.raw in tier2_speeds:
            n.download_speed = tier2_speeds[n.raw]

    completed = bool(t1_complete and t2_complete and not timed_out and not error)
    if not completed:
        summary = {
            "tier1_tested": len(tier1_tested),
            "tier1_alive": len(tier1_alive),
            "tier2_tested": len(tier2_tested),
            "tier2_passed": len(tier2_speeds),
            "isolated_tier1_failures": isolated_t1_failures,
            "isolated_tier2_failures": isolated_t2_failures,
            "unsupported_for_verifier": len(unsupported_nodes),
            "total_alive": sum(n.alive is True for n in nodes),
            "unverified": sum(n.alive is None for n in nodes),
            "completed": False,
            "success": False,
            "error": error or "max runtime reached; progress saved",
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary

    nodes_sorted = sorted(
        nodes,
        key=lambda n: (
            0 if n.alive is True else 1 if n.alive is None else 2,
            -(n.download_speed or 0.0),
            n.latency_ms if n.latency_ms is not None else 10**9,
        ),
    )
    live_tmp = LIVE.with_suffix(".jsonl.tmp")
    try:
        with live_tmp.open("w", encoding="utf-8", newline="\n") as f:
            for n in nodes_sorted:
                f.write(
                    json.dumps(n.model_dump(mode="json"), ensure_ascii=False) + "\n"
                )
    except Exception as exc:
        live_tmp.unlink(missing_ok=True)
        summary = {
            "tier1_tested": len(tier1_tested),
            "tier1_alive": len(tier1_alive),
            "tier2_tested": len(tier2_tested),
            "tier2_passed": len(tier2_speeds),
            "isolated_tier1_failures": isolated_t1_failures,
            "isolated_tier2_failures": isolated_t2_failures,
            "total_alive": sum(n.alive is True for n in nodes),
            "unverified": sum(n.alive is None for n in nodes),
            "completed": False,
            "success": False,
            "error": f"live snapshot staging failed: {exc}",
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary

    now = _now()
    live_original = LIVE.read_bytes() if LIVE.exists() else None
    live_attempted = False
    conn = _init_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for n in nodes:
            conn.execute(
                """UPDATE nodes
                   SET alive=?, latency_ms=?, download_speed=?, last_checked=?, node_json=?
                   WHERE uri=?""",
                (
                    None if n.alive is None else int(n.alive),
                    n.latency_ms,
                    n.download_speed,
                    now,
                    json.dumps(n.model_dump(mode="json"), ensure_ascii=False),
                    n.raw,
                ),
            )
        live_attempted = True
        live_tmp.replace(LIVE)
        conn.commit()
    except Exception as exc:
        conn.rollback()
        recovery_error: str | None = None
        if live_attempted:
            try:
                current = LIVE.read_bytes() if LIVE.exists() else None
                if current != live_original:
                    if live_original is None:
                        LIVE.unlink(missing_ok=True)
                    else:
                        restore = LIVE.with_suffix(".jsonl.restore")
                        restore.write_bytes(live_original)
                        restore.replace(LIVE)
            except Exception as recovery_exc:  # pragma: no cover - catastrophic I/O
                recovery_error = str(recovery_exc)
        summary = {
            "tier1_tested": len(tier1_tested),
            "tier1_alive": len(tier1_alive),
            "tier2_tested": len(tier2_tested),
            "tier2_passed": len(tier2_speeds),
            "isolated_tier1_failures": isolated_t1_failures,
            "isolated_tier2_failures": isolated_t2_failures,
            "total_alive": sum(n.alive is True for n in nodes),
            "unverified": sum(n.alive is None for n in nodes),
            "completed": False,
            "success": False,
            "error": (
                f"verification snapshot activation failed: {exc}"
                + (f"; recovery error: {recovery_error}" if recovery_error else "")
            ),
        }
        _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
        return summary
    finally:
        conn.close()
        live_tmp.unlink(missing_ok=True)

    summary = {
        "tier1_tested": len(tier1_tested),
        "tier1_alive": len(tier1_alive),
        "tier2_tested": len(tier2_tested),
        "tier2_passed": len(tier2_speeds),
        "isolated_tier1_failures": isolated_t1_failures,
        "isolated_tier2_failures": isolated_t2_failures,
        "unsupported_for_verifier": len(unsupported_nodes),
        "total_alive": sum(n.alive is True for n in nodes),
        "unverified": sum(n.alive is None for n in nodes),
        "completed": True,
        "success": True,
        # Bind a later emit invocation to this exact private live snapshot.
        # The digest is metadata only and is not exposed by the public status.
        "live_snapshot_sha256": hashlib.sha256(LIVE.read_bytes()).hexdigest(),
    }
    progress_file.unlink(missing_ok=True)
    _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
    return summary


def _publish_logic(strict: bool = False) -> dict:
    """Publish one complete, verified snapshot to the Cloudflare Worker."""
    import httpx

    q = _load_quality()
    min_dl = float(q.get("min_download_speed_mbps", 5))
    top_n = int(q.get("top_n_publish", 100))

    if not LIVE.exists():
        summary = {"published": 0, "success": False, "error": "no live.jsonl"}
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    all_nodes: list[ProxyNode] = []
    invalid_lines = 0
    for line in LIVE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            document = json.loads(line)
            if not isinstance(document, dict):
                raise TypeError("record is not an object")
            node = ProxyNode(**document)
            parser.validate_node_raw(node)
            all_nodes.append(node)
        except Exception:
            invalid_lines += 1

    if invalid_lines:
        summary = {
            "published": 0,
            "success": False,
            "error": f"live.jsonl contains {invalid_lines} invalid records",
        }
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    selected = [n for n in all_nodes if n.alive is True]
    if strict:
        selected = [
            n
            for n in selected
            if n.download_speed is not None and n.download_speed >= min_dl
        ]
    selected.sort(
        key=lambda n: (
            -(n.download_speed if n.download_speed is not None else -1.0),
            n.latency_ms if n.latency_ms is not None else 10**9,
            n.raw,
        )
    )
    selected = selected[:top_n]

    if not selected:
        summary = {
            "published": 0,
            "success": False,
            "strict": strict,
            "error": "no qualifying verified nodes; existing Worker snapshot retained",
        }
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    base = os.environ.get("WORKER_URL", "").strip().rstrip("/")
    if not base:
        summary = {
            "published": 0,
            "success": False,
            "strict": strict,
            "error": "WORKER_URL env not set",
        }
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary
    parsed_worker_url = urlparse(base)
    loopback = parsed_worker_url.hostname in {"localhost", "127.0.0.1", "::1"}
    secure_transport = parsed_worker_url.scheme.lower() == "https"
    local_development = parsed_worker_url.scheme.lower() == "http" and loopback
    if (
        not parsed_worker_url.hostname
        or parsed_worker_url.username is not None
        or parsed_worker_url.password is not None
        or not (secure_transport or local_development)
    ):
        summary = {
            "published": 0,
            "success": False,
            "strict": strict,
            "error": (
                "WORKER_URL must use HTTPS; HTTP is permitted only for a "
                "loopback development endpoint"
            ),
        }
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary
    worker_url = f"{base}/admin/import"
    token = os.environ.get("ADMIN_TOKEN")
    if not token:
        console.print(
            "[red]ADMIN_TOKEN env not set — refusing to publish. Set it in GitHub "
            "Secrets (CI) or .env (local). The Worker admin token must NOT be "
            "hardcoded (repo is public)."
        )
        summary = {
            "published": 0,
            "success": False,
            "error": "ADMIN_TOKEN env not set",
        }
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    snapshot_id = f"{int(time.time())}-{uuid.uuid4().hex}"
    payload = {
        "version": 1,
        "snapshot_id": snapshot_id,
        "expected_count": len(selected),
        "nodes": [
            {
                "uri": n.raw,
                "alive": True,
                "latency_ms": n.latency_ms,
                "download_speed": n.download_speed,
                "model": n.model_dump(mode="json"),
            }
            for n in selected
        ],
    }
    try:
        resp = httpx.post(
            worker_url,
            json=payload,
            headers={
                "X-Admin-Token": token,
                "Content-Type": "application/json",
            },
            timeout=120.0,
        )
        body = resp.text[:1000]
        if not 200 <= resp.status_code < 300:
            raise RuntimeError(f"Worker import HTTP {resp.status_code}: {body}")
        try:
            result = resp.json()
        except ValueError as e:
            raise RuntimeError("Worker import returned non-JSON response") from e
        ok = (
            result.get("ok") is True
            and result.get("complete") is True
            and result.get("snapshot_id") == snapshot_id
            and result.get("imported") == len(selected)
            and result.get("expected") == len(selected)
            and result.get("model_persisted") is True
        )
        if not ok:
            raise RuntimeError(f"Worker import contract mismatch: {body}")
        console.print(
            f"[green]Worker snapshot {snapshot_id} imported: {len(selected)} nodes"
        )
        summary = {
            "published": len(selected),
            "http_status": resp.status_code,
            "snapshot_id": snapshot_id,
            "strict": strict,
            "success": True,
        }
    except Exception as e:
        console.print(f"[red]publish POST failed: {e}")
        summary = {
            "published": 0,
            "success": False,
            "strict": strict,
            "snapshot_id": snapshot_id,
            "error": str(e),
        }

    _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
    return summary


# ---- typer commands ----
def _ensure_success(stage: str, summary: dict) -> None:
    """Turn structured stage failures into a non-zero CLI exit status."""
    if summary.get("success") is False or summary.get("error"):
        console.print(f"[red]{stage} failed: {summary.get('error', 'unknown error')}")
        raise typer.Exit(code=1)


@app.command()
def fetch() -> None:
    """Fetch enabled sources into state/staging.jsonl."""
    console.rule("[bold cyan]fetch")
    summary = _fetch_logic()
    _print_table("fetch summary", summary)
    _ensure_success("fetch", summary)


@app.command()
def parse() -> None:
    """Parse staging.jsonl -> ProxyNode -> dedup -> SQLite nodes."""
    console.rule("[bold cyan]parse")
    summary = _parse_logic()
    _print_table("parse summary", summary)
    _ensure_success("parse", summary)


@app.command()
def verify(
    max_runtime: int = typer.Option(
        0,
        "--max-runtime",
        "-t",
        help="Max wall-clock seconds before graceful pause (saves progress, resumes next run). 0 = no limit.",
    ),
) -> None:
    """Two-tier quality screening via clash-speedtest (latency + download speed)."""
    console.rule("[bold yellow]verify (Tier1 latency + Tier2 download)")
    summary = _verify_logic(max_runtime=max_runtime or None)
    _print_table("verify summary", summary)
    _ensure_success("verify", summary)


@app.command(name="emit")
def emit_cmd() -> None:
    """Emit the verified live snapshot and sanitized public pipeline status."""
    console.rule("[bold green]emit")
    verify_summary, status_error = _load_completed_verify_summary()
    if verify_summary is None:
        summary = {
            "nodes": 0,
            "clash_proxies": 0,
            "singbox_outbounds": 0,
            "rss_items": 0,
            "success": False,
            "error": status_error or "preceding verify metadata is unavailable",
        }
    else:
        summary = emit.emit_all(verify_summary=verify_summary)
    _write_last_run(1, {"emit": summary}, extra={"last_stage_cmd": "emit"})
    _print_table("emit summary", summary)
    _ensure_success("emit", summary)


@app.command(name="validate-output-status")
def validate_output_status_cmd(
    require_healthy: bool = typer.Option(
        True,
        "--require-healthy/--allow-unknown",
        help="Require the CI-produced healthy state instead of a bootstrap unknown state.",
    ),
) -> None:
    """Validate pipeline-status.json and its public artifact count contract."""

    console.rule("[bold green]validate output status")
    try:
        summary = emit.validate_pipeline_status_artifact(
            require_healthy=require_healthy
        )
    except emit.InvalidPipelineStatus as exc:
        summary = {"success": False, "error": str(exc)}
    _print_table("pipeline status validation", summary)
    _ensure_success("validate-output-status", summary)


@app.command()
def publish(
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Require the configured download-speed floor. Both modes exclude unverified nodes.",
    ),
) -> None:
    """Publish top-N alive nodes (by download_speed) to the Cloudflare Worker."""
    console.rule("[bold magenta]publish")
    summary = _publish_logic(strict=strict)
    _print_table("publish summary", summary)
    _ensure_success("publish", summary)


@app.command()
def dashboard(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Loopback address used by the local dashboard server.",
    ),
    port: int = typer.Option(
        8765,
        "--port",
        min=0,
        max=65535,
        help="Local TCP port. Use 0 to select an available port.",
    ),
    open_browser: bool = typer.Option(
        False,
        "--open/--no-open",
        help="Open the dashboard URL in the default browser after startup.",
    ),
) -> None:
    """Run the loopback-only operations dashboard and node IP checker."""
    from dashboard.server import serve

    try:
        serve(ROOT, host=host, port=port, open_browser=open_browser)
    except (OSError, ValueError) as exc:
        console.print(f"[red]dashboard failed: {exc}")
        raise typer.Exit(code=2) from exc


@app.command(name="github-dork")
def github_dork_cmd() -> None:
    """GitHub secret dorking: code search + self-org trufflehog/gitleaks audit."""
    console.rule("[bold magenta]github-dork (A4)")
    summary = github_dork.run()
    # github_dork.run() already merges a rich stages["github-dork"] entry into
    # last-run.json via its _update_last_run. Re-mirror it here too so the
    # flat top-level {stage,counts,last_stage_cmd} stays consistent.
    github_dork._update_last_run(summary)
    _print_table("github-dork summary", summary)
    _ensure_success("github-dork", summary)


@app.command(name="publish-resin")
def publish_resin() -> None:
    """Publish alive + gray nodes to the local resin proxy pool."""
    console.rule("[bold magenta]publish-resin")
    summary = resin_publisher.run()
    _write_last_run(
        1, {"publish-resin": summary}, extra={"last_stage_cmd": "publish-resin"}
    )
    _print_table("resin summary", summary)
    _ensure_success("publish-resin", summary)


def _publish_self_logic() -> dict:
    """Stage 15 (A7): rebuild URIs from config/self_nodes.yaml -> state/self_nodes.jsonl,
    then pour them into resin under the 'self-owned' subscription (separate from the
    merged free-proxy-aggregator pool so operator VPS nodes stay identifiable).
    """
    gen = self_nodes.run()
    uris = gen.get("uris", [])
    summary = resin_publisher.publish_to_resin(
        "self-owned", uris, replace_existing=True
    )
    summary["nodes_loaded"] = gen.get("nodes", 0)
    summary["self_nodes_path"] = gen.get("path")
    return summary


@app.command(name="publish-self")
def publish_self() -> None:
    """Publish self-owned VPS nodes (Stage 15) to resin subscription 'self-owned'."""
    console.rule("[bold magenta]publish-self (self-owned VPS pool)")
    summary = _publish_self_logic()
    _write_last_run(
        1, {"publish-self": summary}, extra={"last_stage_cmd": "publish-self"}
    )
    _print_table("self-owned summary", summary)
    _ensure_success("publish-self", summary)


@app.command(name="ct-recon")
def ct_recon_cmd() -> None:
    """CT logs + passive DNS recon (Stage 16). Passive, no active probing."""
    console.rule("[bold cyan]ct-recon (CT logs + passive DNS)")
    summary = ct_recon.run()
    _write_last_run(1, {"ct-recon": summary}, extra={"last_stage_cmd": "ct-recon"})
    _print_table("ct-recon summary", summary)
    _ensure_success("ct-recon", summary)


@app.command(name="v2board-recon")
def v2board_recon_cmd(
    exploit: bool = typer.Option(
        False, "--exploit", help="exploit mode (ONLY self-owned/authorized targets)"
    ),
) -> None:
    """Stage 17 (A2): V2Board/Xboard fingerprint (recon) + CVE-2026-39912 chain
    (exploit, only against config/v2board_targets.yaml self-owned targets)."""
    mode = "exploit (self-owned targets)" if exploit else "recon (fingerprint)"
    console.rule(f"[bold red]v2board-recon — {mode}")
    summary = v2board_recon.run(exploit=exploit)
    _write_last_run(
        1, {"v2board-recon": summary}, extra={"last_stage_cmd": "v2board-recon"}
    )
    _print_table("v2board-recon summary", summary)
    _ensure_success("v2board-recon", summary)


@app.command(name="tg-recon")
def tg_recon_cmd() -> None:
    """Stage 18 (A5): TG web-preview scrape + 7-point honeytrap triage."""
    console.rule("[bold cyan]tg-recon (TG web-preview + honeytrap triage)")
    summary = tg_recon.run()
    _write_last_run(1, {"tg-recon": summary}, extra={"last_stage_cmd": "tg-recon"})
    _print_table("tg-recon summary", summary)
    _ensure_success("tg-recon", summary)


@app.command(name="all")
def all_cmd() -> None:
    """Run the fail-closed core pipeline; optional gray/self pools stay explicit."""
    console.rule("[bold magenta]all (full pipeline)")
    counts: dict[str, dict] = {}

    console.print("[bold cyan]== fetch ==")
    counts["fetch"] = _fetch_logic()
    console.print(f"  {counts['fetch']}")
    _ensure_success("fetch", counts["fetch"])

    console.print("[bold cyan]== parse ==")
    counts["parse"] = _parse_logic()
    console.print(
        f"  raw={counts['parse'].get('raw_nodes')} unique={counts['parse'].get('unique')}"
    )
    _ensure_success("parse", counts["parse"])

    console.print("[bold cyan]== verify (Tier1+Tier2) ==")
    counts["verify"] = _verify_logic()
    console.print(f"  {counts['verify']}")
    _ensure_success("verify", counts["verify"])

    console.print("[bold cyan]== emit ==")
    counts["emit"] = emit.emit_all(verify_summary=counts["verify"])
    console.print(f"  {counts['emit']}")
    _ensure_success("emit", counts["emit"])

    console.print("[bold cyan]== publish ==")
    counts["publish"] = _publish_logic(strict=True)
    console.print(f"  {counts['publish']}")
    _ensure_success("publish", counts["publish"])

    _print_table(
        "all summary",
        {
            stage: json.dumps(result, ensure_ascii=False)[:100]
            for stage, result in counts.items()
        },
    )
    _write_last_run(1, counts, extra={"last_stage_cmd": "all"})


def _print_table(title: str, data: dict) -> None:
    t = Table("metric", "value", title=title)
    for k, v in data.items():
        t.add_row(str(k), str(v))
    console.print(t)


if __name__ == "__main__":
    app()
