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
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# Bootstrap: allow bare `python src/aggregator/cli.py <cmd>` as the contract specifies,
# not just `python -m aggregator.cli`. Insert src/ on path before relative imports.
if __package__ is None or "" in __name__.split("."):
    _SRC = Path(__file__).resolve().parents[1]
    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))
    from aggregator import fetcher, parser, dedupe, emit, source_audit  # noqa: E402
    from aggregator import gray_sources, resin_publisher, scanner  # noqa: E402
    from aggregator import self_nodes, ct_recon  # noqa: E402
    from aggregator import github_dork  # noqa: E402
    from aggregator import v2board_recon, tg_recon  # noqa: E402
    from aggregator.models import (  # noqa: E402
        SEMANTIC_KEY_VERSION,
        STABLE_SAMPLE_SEED,
        ProxyNode,
        Source,
    )
else:
    from . import fetcher, parser, dedupe, emit, source_audit
    from . import gray_sources, resin_publisher, scanner  # noqa: E402
    from . import self_nodes, ct_recon  # noqa: E402
    from . import github_dork  # noqa: E402
    from . import v2board_recon, tg_recon  # noqa: E402
    from .models import SEMANTIC_KEY_VERSION, STABLE_SAMPLE_SEED, ProxyNode, Source

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
CANARY_GATE_SCHEMA_VERSION = 1
CANARY_HISTORY_SCHEMA_VERSION = 2
TIER1_BATCH_SIZE = 50
TIER2_BATCH_SIZE = 30
DEFAULT_MAX_TOTAL_NODES = 1800
DEFAULT_CANARY_MAX_TOTAL_NODES = 650
DEFAULT_CANARY_HISTORY = "state/source-canary-history.jsonl"
DEFAULT_CANARY_REQUIRED_RUNS = 3
DEFAULT_CANARY_WINDOW_HOURS = 48


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


def _stable_node_hash(node: ProxyNode) -> str:
    """Return the deterministic ranking key used by ``stable_hash`` sampling."""

    payload = f"{STABLE_SAMPLE_SEED}\0{dedupe.normalize_node(node)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sample_source_nodes(
    nodes: list[ProxyNode], source: Source
) -> tuple[list[ProxyNode], int, int]:
    """Deduplicate and optionally sample one source's nodes.

    The returned tuple is ``(accepted, semantic_duplicates, truncated)``.  A
    source is deduplicated before applying its limit so ``max_nodes`` counts
    accepted semantic connections rather than repeated URI spellings.  The
    final list retains the source's original order among selected nodes; only
    membership is hash-ranked, which keeps existing snapshots readable while
    making the selected set independent of upstream ordering.
    """

    if source.sample_strategy != "stable_hash":
        # ``Source`` validation normally catches this. Keep the guard here so
        # callers constructing a model without validation still fail closed.
        raise ValueError(
            f"unsupported source sample strategy: {source.sample_strategy}"
        )

    unique, dropped = dedupe.dedupe_nodes(nodes)
    max_nodes = source.max_nodes
    if max_nodes is None or len(unique) <= max_nodes:
        return unique, len(dropped), 0

    ranked = sorted(
        unique,
        key=lambda node: (_stable_node_hash(node), node.dedup_key(), node.raw),
    )
    selected_keys = {node.dedup_key() for node in ranked[:max_nodes]}
    accepted = [node for node in unique if node.dedup_key() in selected_keys]
    return accepted, len(dropped), len(unique) - len(accepted)


def _parse_node_cap() -> tuple[int, str]:
    """Read the hard accepted-node cap for normal or canary parsing."""

    quality = _load_quality()
    if not isinstance(quality, dict):
        raise ValueError("quality configuration must be a mapping")
    canary = os.environ.get("SOURCE_CANARY") == "1"
    key = "canary_max_total_nodes" if canary else "max_total_nodes"
    default = DEFAULT_CANARY_MAX_TOTAL_NODES if canary else DEFAULT_MAX_TOTAL_NODES
    value = quality.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"quality {key} must be a positive integer")
    return value, key


def _parse_logic() -> dict:
    if not STAGING.exists():
        console.print("[red]no staging.jsonl — parse aborted")
        summary = {
            "raw_nodes": 0,
            "sampled": 0,
            "unique": 0,
            "duplicates": 0,
            "truncated_by_source": {},
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
    source_models: dict[str, Source] = {}
    source_config_errors: dict[str, str] = {}
    for sid in sorted(enabled_ids):
        try:
            source_models[sid] = Source.model_validate(sources_by_id[sid])
        except (TypeError, ValueError) as exc:
            source_config_errors[sid] = str(exc)

    # Keep the pre-dedup parser count for the existing ``raw_nodes`` metric;
    # ``accepted_nodes`` is the bounded projection persisted to the snapshot.
    raw_nodes: list[ProxyNode] = []
    accepted_nodes: list[ProxyNode] = []
    src_counts: dict[str, int] = {}
    source_duplicate_counts: dict[str, int] = {}
    truncated_by_source: dict[str, int] = {}
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
        if sid in source_config_errors:
            invalid_records += 1
            continue
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
        try:
            accepted, source_duplicates, truncated = _sample_source_nodes(
                nodes, source_models[sid]
            )
        except (TypeError, ValueError):
            invalid_records += 1
            continue
        accepted_nodes.extend(accepted)
        src_counts[sid] = len(accepted)
        source_duplicate_counts[sid] = source_duplicates
        if truncated:
            truncated_by_source[sid] = truncated

    missing_sources = sorted(enabled_ids - staged_sources)
    empty_sources = sorted(sid for sid in enabled_ids if src_counts.get(sid, 0) == 0)
    sampled_count = len(accepted_nodes)
    source_duplicates = sum(source_duplicate_counts.values())
    if (
        invalid_records
        or missing_sources
        or empty_sources
        or rejected_sources
        or duplicate_sources
    ):
        summary = {
            "raw_nodes": len(raw_nodes),
            "sampled": sampled_count,
            "unique": 0,
            "duplicates": source_duplicates,
            "by_source": src_counts,
            "truncated_by_source": truncated_by_source,
            "success": False,
            "invalid_records": invalid_records,
            "source_config_errors": source_config_errors,
            "missing_sources": missing_sources,
            "empty_sources": empty_sources,
            "rejected_sources": sorted(rejected_sources),
            "duplicate_sources": sorted(duplicate_sources),
            "error": "staging snapshot failed validation; prior DB/live snapshot retained",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary

    try:
        max_total_nodes, max_total_key = _parse_node_cap()
    except (TypeError, ValueError) as exc:
        summary = {
            "raw_nodes": len(raw_nodes),
            "sampled": sampled_count,
            "unique": 0,
            "duplicates": source_duplicates,
            "by_source": src_counts,
            "truncated_by_source": truncated_by_source,
            "success": False,
            "error": f"invalid quality node cap: {exc}",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary
    if sampled_count > max_total_nodes:
        summary = {
            "raw_nodes": len(raw_nodes),
            "sampled": sampled_count,
            "unique": 0,
            "duplicates": source_duplicates,
            "by_source": src_counts,
            "truncated_by_source": truncated_by_source,
            "success": False,
            "error": (
                f"accepted sampled node count {sampled_count} exceeds "
                f"{max_total_key}={max_total_nodes}; prior DB/live snapshot retained"
            ),
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary

    unique, dropped = dedupe.dedupe_nodes(accepted_nodes)
    chash = dedupe.content_hash(unique)
    if not unique:
        summary = {
            "raw_nodes": len(raw_nodes),
            "sampled": sampled_count,
            "unique": 0,
            "duplicates": source_duplicates + len(dropped),
            "by_source": src_counts,
            "truncated_by_source": truncated_by_source,
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
                     :country,NULL,NULL,NULL,:source,:first_seen,:last_checked,
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
                    "country": n.country,
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
            "sampled": sampled_count,
            "duplicates": source_duplicates + len(dropped),
            "by_source": src_counts,
            "truncated_by_source": truncated_by_source,
            "success": False,
            "error": f"snapshot activation failed: {e}{recovery_note}",
        }
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary
    finally:
        conn.close()

    summary = {
        "raw_nodes": len(raw_nodes),
        "sampled": sampled_count,
        "unique": len(unique),
        "duplicates": source_duplicates + len(dropped),
        "by_source": src_counts,
        "truncated_by_source": truncated_by_source,
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
        openvpn_endpoints = {
            f"{proxy.get('server')}:{proxy.get('port')}"
            for proxy in all_proxies
            if proxy.get("type") == "openvpn"
        }
        prefilter_proxies = [
            proxy for proxy in all_proxies if proxy.get("type") != "openvpn"
        ]
        reachable = tcp_prefilter.run(prefilter_proxies)
        # OpenVPN may use UDP and therefore cannot be screened with a TCP SYN.
        # Its protocol handshake is exercised by the pinned Mihomo verifier.
        reachable.update(openvpn_endpoints)
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


def _verify_candidate_isolated(
    nodes: list[ProxyNode], *, max_runtime: int | None = None
) -> dict:
    """Run the production verifier against candidate nodes in a temp snapshot.

    ``_verify_logic`` intentionally operates on the configured SQLite/live
    projections.  Canary review must use the exact same verifier contract while
    keeping those projections untouched, so this adapter swaps only the four
    runtime paths for the duration of the call and restores them unconditionally.
    """

    if not nodes:
        return {
            "completed": False,
            "success": False,
            "tier1_tested": 0,
            "tier1_alive": 0,
            "tier2_tested": 0,
            "tier2_passed": 0,
            "error": "candidate has no verifier-eligible nodes",
        }

    global STATE, DB, LIVE, LAST_RUN
    original_paths = (STATE, DB, LIVE, LAST_RUN)
    try:
        with tempfile.TemporaryDirectory(prefix="source-canary-") as temp_dir:
            temp_root = Path(temp_dir)
            temp_state = temp_root / "state"
            temp_state.mkdir(parents=True, exist_ok=True)
            STATE = temp_state
            DB = temp_root / "nodes.db"
            LIVE = temp_state / "live.jsonl"
            LAST_RUN = temp_state / "last-run.json"

            conn = _init_db()
            try:
                for node in nodes:
                    snapshot_node = node.model_copy(
                        update={
                            "alive": None,
                            "latency_ms": None,
                            "download_speed": None,
                        }
                    )
                    conn.execute(
                        """INSERT INTO nodes(
                               uri, node_json, source, alive, latency_ms,
                               download_speed
                           ) VALUES(?,?,?,?,?,?)""",
                        (
                            snapshot_node.raw,
                            json.dumps(
                                snapshot_node.model_dump(mode="json"),
                                ensure_ascii=False,
                            ),
                            snapshot_node.source,
                            None,
                            None,
                            None,
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

            summary = _verify_logic(max_runtime=max_runtime)
            if LIVE.exists():
                verified_nodes: list[ProxyNode] = []
                for line in LIVE.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        verified_nodes.append(
                            ProxyNode.model_validate(json.loads(line))
                        )
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                tier1_nodes = [node for node in verified_nodes if node.alive is True]
                tier2_nodes = [
                    node
                    for node in tier1_nodes
                    if isinstance(node.download_speed, (int, float))
                ]
                latencies = sorted(
                    node.latency_ms
                    for node in tier1_nodes
                    if isinstance(node.latency_ms, int)
                )
                summary["tier1_alive_keys"] = sorted(
                    {node.dedup_key() for node in tier1_nodes}
                )
                summary["tier2_passed_keys"] = sorted(
                    {node.dedup_key() for node in tier2_nodes}
                )
                summary["tier2_protocol_counts"] = {
                    proto: sum(node.proto == proto for node in tier2_nodes)
                    for proto in sorted({node.proto for node in tier2_nodes})
                }
                # Keep the protocol beside the opaque semantic key so the
                # batch diversity gate can distinguish genuinely net-new
                # protocol families from nodes already in the baseline.
                summary["tier2_protocol_by_key"] = {
                    node.dedup_key(): node.proto for node in tier2_nodes
                }
                if latencies:
                    middle = len(latencies) // 2
                    summary["median_latency_ms"] = (
                        float(latencies[middle])
                        if len(latencies) % 2
                        else (latencies[middle - 1] + latencies[middle]) / 2
                    )
            return summary
    except Exception as exc:  # pragma: no cover - defensive integration guard
        return {
            "completed": False,
            "success": False,
            "tier1_tested": 0,
            "tier1_alive": 0,
            "tier2_tested": 0,
            "tier2_passed": 0,
            "error": f"isolated candidate verifier failed: {type(exc).__name__}: {exc}",
        }
    finally:
        STATE, DB, LIVE, LAST_RUN = original_paths


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


def _audit_path(value: Path | None, default: Path) -> Path:
    path = value if value is not None else default
    return path if path.is_absolute() else ROOT / path


def _apply_canary_gates(
    report: dict,
    *,
    verify_enabled: bool,
    baseline_path: Path,
    mirror_threshold: float = 0.80,
    max_unsupported_ratio: float = 0.20,
    max_overlap_ratio: float = 0.90,
    reject_private_reserved: bool = True,
    required_runs: int = DEFAULT_CANARY_REQUIRED_RUNS,
    minimum_window_hours: int = DEFAULT_CANARY_WINDOW_HOURS,
    require_batch_diversity: bool = True,
) -> dict:
    """Apply one run's source-quality gates to a completed audit report.

    The separate ``_update_canary_history`` step adds the multi-run promotion
    gate without making the first two scheduled canaries fail just because
    they are still warming the required history window.
    """

    baseline_nodes, _invalid, baseline_error = source_audit.load_baseline(baseline_path)
    baseline_keys = {node.dedup_key() for node in baseline_nodes}
    overall_reasons: list[str] = []
    net_new_tier2_protocols: set[str] = set()
    passing_sources = 0

    for result in report.get("results", []):
        reasons: list[str] = []
        source_id = str(result.get("id") or "unknown")
        unique_count = int(result.get("unique", 0) or 0)
        if result.get("status") != "ok":
            reasons.append(f"audit status is {result.get('status')}")
        http_status = result.get("http_status")
        if (
            isinstance(http_status, bool)
            or not isinstance(http_status, int)
            or not 200 <= http_status < 300
        ):
            reasons.append(f"fetch status {http_status!r} is not HTTP 2xx")
        if unique_count < 1:
            reasons.append("parser produced no accepted nodes")
        unsupported_ratio = result.get("unsupported_ratio")
        if not isinstance(unsupported_ratio, (int, float)):
            reasons.append("unsupported/invalid ratio could not be measured")
        elif unsupported_ratio > max_unsupported_ratio:
            reasons.append(
                "unsupported/invalid ratio "
                f"{unsupported_ratio:.3f} exceeds {max_unsupported_ratio:.2f}"
            )
        if (
            reject_private_reserved
            and int(result.get("private_reserved_count", 0) or 0) > 0
        ):
            reasons.append("source contains private or reserved endpoints")
        if float(result.get("overlap_ratio", 0.0) or 0.0) > max_overlap_ratio:
            reasons.append(f"semantic overlap exceeds {max_overlap_ratio:.2f}")

        eligible_mirrors: list[str] = []
        rejected_mirrors: list[str] = []
        unavailable_mirrors: list[str] = []
        for mirror_url, value in (result.get("mirror_jaccards") or {}).items():
            if isinstance(value, (int, float)) and value >= mirror_threshold:
                eligible_mirrors.append(str(mirror_url))
            elif isinstance(value, (int, float)):
                rejected_mirrors.append(str(mirror_url))
            else:
                unavailable_mirrors.append(str(mirror_url))
        result["mirror_policy"] = {
            "minimum_jaccard": mirror_threshold,
            "production_eligible": sorted(eligible_mirrors),
            "rejected": sorted(rejected_mirrors),
            "unavailable": sorted(unavailable_mirrors),
        }
        fetched_url = str(result.get("fetched_url") or "")
        primary_url = str(result.get("url") or "")
        if fetched_url and fetched_url != primary_url:
            fallback_jaccard = (result.get("mirror_jaccards") or {}).get(fetched_url)
            if (
                not isinstance(fallback_jaccard, (int, float))
                or fallback_jaccard < mirror_threshold
            ):
                reasons.append(
                    "primary fetch failed and fallback mirror is not production-eligible"
                )

        if verify_enabled:
            verification = result.get("verification") or {}
            tier1_alive = int(verification.get("tier1_alive", 0) or 0)
            tier2_passed = int(verification.get("tier2_passed", 0) or 0)
            tier1_minimum = max(5, (unique_count + 9) // 10)
            tier2_minimum = max(5, (unique_count + 19) // 20)
            tier2_keys = {
                str(value)
                for value in verification.pop("tier2_passed_keys", [])
                if isinstance(value, str)
            }
            tier2_protocol_by_key = verification.pop("tier2_protocol_by_key", {})
            if not isinstance(tier2_protocol_by_key, dict):
                tier2_protocol_by_key = {}
            tier1_keys = {
                str(value)
                for value in verification.pop("tier1_alive_keys", [])
                if isinstance(value, str)
            }
            net_new_tier2 = len(tier2_keys - baseline_keys)
            net_new_tier2_protocol_counts: dict[str, int] = {}
            for key in tier2_keys - baseline_keys:
                proto = tier2_protocol_by_key.get(key)
                if isinstance(proto, str) and proto:
                    net_new_tier2_protocol_counts[proto] = (
                        net_new_tier2_protocol_counts.get(proto, 0) + 1
                    )
            # Preserve compatibility with injected verifier summaries that do
            # not yet expose key-to-protocol metadata; the production verifier
            # always supplies it, so real runs use the net-new calculation.
            if not tier2_protocol_by_key:
                protocol_counts = verification.get("tier2_protocol_counts") or {}
                net_new_tier2_protocol_counts = {
                    str(proto): int(count)
                    for proto, count in protocol_counts.items()
                    if isinstance(count, int) and count > 0
                }
            net_new_tier2_protocols.update(net_new_tier2_protocol_counts)
            verification["net_new_tier2"] = net_new_tier2
            verification["net_new_tier2_protocol_counts"] = dict(
                sorted(net_new_tier2_protocol_counts.items())
            )
            verification["tier1_alive_key_count"] = len(tier1_keys)
            verification["tier2_passed_key_count"] = len(tier2_keys)
            verification["tier1_alive_key_sha256"] = hashlib.sha256(
                "\n".join(sorted(tier1_keys)).encode("ascii")
            ).hexdigest()
            verification["tier2_passed_key_sha256"] = hashlib.sha256(
                "\n".join(sorted(tier2_keys)).encode("ascii")
            ).hexdigest()
            result["verification"] = verification

            if verification.get("success") is not True:
                reasons.append(
                    str(verification.get("error") or "candidate verification failed")
                )
            if tier1_alive < tier1_minimum:
                reasons.append(f"Tier-1 alive {tier1_alive} is below {tier1_minimum}")
            if tier2_passed < tier2_minimum:
                reasons.append(f"Tier-2 passed {tier2_passed} is below {tier2_minimum}")
            if net_new_tier2 < 5:
                reasons.append(f"net-new Tier-2 {net_new_tier2} is below 5")

        result["gate"] = {
            "passed": not reasons,
            "reasons": reasons,
            "mirror_jaccard_minimum": mirror_threshold,
            "max_unsupported_ratio": max_unsupported_ratio,
        }
        if reasons:
            overall_reasons.extend(f"{source_id}: {reason}" for reason in reasons)
        else:
            passing_sources += 1

    if report.get("baseline_error") or baseline_error:
        overall_reasons.append(str(report.get("baseline_error") or baseline_error))
    if (
        not verify_enabled
        and int((report.get("totals") or {}).get("net_new", 0) or 0) < 5
    ):
        overall_reasons.append("cheap audit net-new nodes are below 5")
    batch_diversity_passed = False
    if verify_enabled and require_batch_diversity:
        batch_diversity_reasons: list[str] = []
        if len(net_new_tier2_protocols) < 2:
            batch_diversity_reasons.append(
                "net-new Tier-2 batch covers fewer than two protocols"
            )
        diversity_protocols = {"hysteria2", "tuic", "juicity", "ssr"}
        if not net_new_tier2_protocols.intersection(diversity_protocols):
            batch_diversity_reasons.append(
                "net-new Tier-2 batch lacks hysteria2, tuic, juicity, or ssr"
            )
        batch_diversity_passed = not batch_diversity_reasons
        overall_reasons.extend(batch_diversity_reasons)

    results = report.get("results") or []
    report["gate"] = {
        "passed": bool(results) and not overall_reasons,
        "reasons": overall_reasons,
        "passing_sources": passing_sources,
        "required_successful_runs": required_runs,
        "minimum_window_hours": minimum_window_hours,
        "tier2_protocols": sorted(net_new_tier2_protocols),
        "net_new_tier2_protocols": sorted(net_new_tier2_protocols),
        "batch_diversity_required": require_batch_diversity,
        "batch_diversity_passed": batch_diversity_passed,
    }
    report["gate_config"] = {
        "http_status": "2xx",
        "max_unsupported_ratio": max_unsupported_ratio,
        "max_overlap_ratio": max_overlap_ratio,
        "max_private_reserved_ratio": 0.0 if reject_private_reserved else 1.0,
        "mirror_jaccard_minimum": mirror_threshold,
        "tier1_alive": "max(5, ceil(10% * sampled_unique))",
        "tier2_passed": "max(5, ceil(5% * sampled_unique))",
        "net_new_tier2": 5,
        "batch_diversity_required": require_batch_diversity,
    }
    report["gate"]["config"] = report["gate_config"]
    report["gate_passed"] = report["gate"]["passed"]
    report["gate_reasons"] = overall_reasons
    report["success"] = report["gate"]["passed"]
    if isinstance(report.get("totals"), dict):
        report["totals"]["success"] = report["success"]
        report["totals"]["ok"] = report["success"]
    return report


def _candidate_set_fingerprint(
    records: list[dict], settings: dict | None = None
) -> str:
    """Bind canary history to one immutable candidate/sampling projection."""

    projection = []
    for record in records:
        projection.append(
            {
                "id": str(record.get("id") or ""),
                "canonical": source_audit.canonicalize_url(
                    str(record.get("canonical") or record.get("url") or "")
                ),
                "format": str(record.get("format") or ""),
                "candidate_round": record.get("candidate_round"),
                "tier": record.get("tier"),
                "enabled": record.get("enabled"),
                "endpoint_policy": str(record.get("endpoint_policy") or ""),
                "max_nodes": record.get("max_nodes"),
                "sample_strategy": str(record.get("sample_strategy") or ""),
                "mirrors": sorted(
                    {
                        source_audit.canonicalize_url(str(value))
                        for value in (record.get("mirrors") or [])
                    }
                ),
            }
        )
    payload = json.dumps(
        {
            "candidates": sorted(projection, key=lambda value: value["id"]),
            "settings": settings or {},
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _history_timestamp(value: object) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _candidate_history_projection(
    report: dict,
    result: dict,
    *,
    candidate_config_sha256: str,
) -> dict:
    """Bind one canary run to its baseline and sampled upstream content."""

    baseline = report.get("baseline") or {}
    totals = report.get("totals") or {}
    baseline_sha256 = baseline.get("sha256")
    if baseline_sha256 is None:
        baseline_sha256 = totals.get("baseline_sha256")
    baseline_count = baseline.get("nodes")
    if baseline_count is None:
        baseline_count = totals.get("baseline_count")

    sample_projection = {
        "semantic_sha256": result.get("sha256") or result.get("content_hash"),
        "node_set_sha256": result.get("node_set_sha256"),
        "unique": result.get("unique"),
        "unique_before_cap": result.get("unique_before_cap"),
        "sampled_out": result.get("sampled_out"),
        "capped": result.get("capped"),
    }
    sample_projection_sha256 = hashlib.sha256(
        json.dumps(
            sample_projection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "candidate_config_sha256": candidate_config_sha256,
        "baseline_sha256": baseline_sha256,
        "baseline_count": baseline_count,
        "body_sha256": result.get("body_sha256"),
        "content_sha256": result.get("content_sha256"),
        "node_set_sha256": result.get("node_set_sha256"),
        "sample_projection_sha256": sample_projection_sha256,
        "sample_projection": sample_projection,
    }


def _projection_sha256(projection: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            projection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _update_canary_history(
    report: dict,
    *,
    history_path: Path,
    candidate_set_sha256: str,
    candidate_fingerprints: dict[str, str] | None = None,
    candidate_diversity_requirements: dict[str, bool] | None = None,
    required_runs: int = DEFAULT_CANARY_REQUIRED_RUNS,
    minimum_window_hours: int = DEFAULT_CANARY_WINDOW_HOURS,
) -> dict:
    """Persist a compact run summary and calculate promotion readiness."""

    required_runs = max(1, int(required_runs))
    minimum_window_hours = max(0, int(minimum_window_hours))
    previous = source_audit.load_history(history_path)
    run_id = str(report.get("run_id") or uuid.uuid4().hex)
    generated_at = str(
        report.get("generated_at")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    candidate_summaries: dict[str, dict] = {}
    candidate_projections: dict[str, dict] = {}
    history_candidate_fingerprints: dict[str, str] = {}
    for result in report.get("results") or []:
        source_id = str(result.get("id") or "")
        verification = result.get("verification") or {}
        candidate_config_sha256 = (candidate_fingerprints or {}).get(
            source_id
        ) or candidate_set_sha256
        projection = _candidate_history_projection(
            report,
            result,
            candidate_config_sha256=candidate_config_sha256,
        )
        history_fingerprint = _projection_sha256(projection)
        candidate_projections[source_id] = projection
        history_candidate_fingerprints[source_id] = history_fingerprint
        candidate_summaries[source_id] = {
            "passed": (result.get("gate") or {}).get("passed") is True,
            "tier1_alive": int(verification.get("tier1_alive", 0) or 0),
            "tier2_passed": int(verification.get("tier2_passed", 0) or 0),
            "net_new_tier2": int(verification.get("net_new_tier2", 0) or 0),
            "history_fingerprint": history_fingerprint,
        }

    entry = {
        "version": CANARY_HISTORY_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "baseline_sha256": (report.get("baseline") or {}).get("sha256"),
        "baseline_count": (report.get("baseline") or {}).get("nodes"),
        "gate_config_sha256": hashlib.sha256(
            json.dumps(
                report.get("gate_config") or {},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "candidate_set_sha256": candidate_set_sha256,
        # Preserve the original configuration-only field for existing readers;
        # content-bound evidence is kept separately so legacy entries cannot
        # attest a newly fetched candidate payload.
        "candidate_fingerprints": dict(candidate_fingerprints or {}),
        "candidate_history_fingerprints": history_candidate_fingerprints,
        "candidate_projections": candidate_projections,
        "verify_enabled": report.get("verify_enabled") is True,
        "run_gate_passed": (report.get("gate") or {}).get("passed") is True,
        "batch_diversity_passed": (report.get("gate") or {}).get(
            "batch_diversity_passed"
        )
        is True,
        "net_new_tier2_protocols": list(
            (report.get("gate") or {}).get("net_new_tier2_protocols") or []
        ),
        "candidates": candidate_summaries,
    }
    history = [item for item in previous if str(item.get("run_id") or "") != run_id]
    history.append(entry)
    history.sort(
        key=lambda item: (
            _history_timestamp(item.get("generated_at")) or 0.0,
            str(item.get("run_id") or ""),
        )
    )
    history_error: str | None = None
    try:
        source_audit.write_history(history_path, history)
    except Exception as exc:
        history_error = f"{type(exc).__name__}: {exc}"

    promotion_reasons: list[str] = []
    ready_sources = 0
    for result in report.get("results") or []:
        source_id = str(result.get("id") or "")
        # Promotion history is tracked per candidate.  A failed verified run
        # for this candidate breaks its consecutive streak, while an unrelated
        # candidate in the same round may continue accumulating evidence.
        successful_runs: dict[str, float] = {}
        batch_diversity_evidence = False
        requires_batch_diversity = bool(
            (candidate_diversity_requirements or {}).get(source_id, False)
        )
        current_candidate_fingerprint = history_candidate_fingerprints.get(source_id)
        for item in history:
            if item.get("verify_enabled") is not True:
                continue
            item_candidates = item.get("candidates") or {}
            if source_id not in item_candidates:
                continue
            item_candidate_fingerprint = (
                item.get("candidate_history_fingerprints") or {}
            ).get(source_id)
            if current_candidate_fingerprint:
                same_projection = (
                    item_candidate_fingerprint == current_candidate_fingerprint
                )
            else:
                # Backward-compatible path for callers that predate the
                # per-candidate projection field.
                same_projection = (
                    item.get("candidate_set_sha256") == candidate_set_sha256
                )
            if not same_projection:
                # A verified run under different baseline/content/config starts
                # a new streak even if the source later reverts to old bytes.
                successful_runs.clear()
                batch_diversity_evidence = False
                continue
            candidate_summary = item_candidates.get(source_id) or {}
            if candidate_summary.get("passed") is not True:
                successful_runs.clear()
                batch_diversity_evidence = False
                continue
            if item.get("batch_diversity_passed") is True:
                batch_diversity_evidence = True
            timestamp = _history_timestamp(item.get("generated_at"))
            if timestamp is not None:
                successful_runs[str(item.get("run_id") or timestamp)] = timestamp
        timestamps = sorted(successful_runs.values())
        span_hours = (
            (timestamps[-1] - timestamps[0]) / 3600.0 if len(timestamps) >= 2 else 0.0
        )
        ready = (
            len(timestamps) >= required_runs
            and span_hours >= minimum_window_hours
            and (result.get("gate") or {}).get("passed") is True
            and (not requires_batch_diversity or batch_diversity_evidence)
        )
        result["promotion_history"] = {
            "ready": ready,
            "successful_runs": len(timestamps),
            "required_successful_runs": required_runs,
            "window_hours": round(span_hours, 3),
            "minimum_window_hours": minimum_window_hours,
            "batch_diversity_required": requires_batch_diversity,
            "batch_diversity_evidence": batch_diversity_evidence,
            "first_success_at": (
                datetime.fromtimestamp(timestamps[0], timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                if timestamps
                else None
            ),
            "latest_success_at": (
                datetime.fromtimestamp(timestamps[-1], timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                if timestamps
                else None
            ),
        }
        if ready:
            ready_sources += 1
        else:
            promotion_reasons.append(
                f"{source_id}: requires {required_runs} successful verified runs "
                f"across {minimum_window_hours}h (has {len(timestamps)} across "
                f"{span_hours:.1f}h)"
            )

    run_gate = dict(report.get("gate") or {})
    if run_gate.get("passed") is not True:
        promotion_reasons.extend(
            str(reason) for reason in run_gate.get("reasons") or []
        )
    if history_error:
        promotion_reasons.append(f"canary history write failed: {history_error}")
    result_count = len(report.get("results") or [])
    promotion_ready = (
        result_count > 0
        and ready_sources == result_count
        and run_gate.get("passed") is True
        and history_error is None
    )
    report["run_gate"] = run_gate
    report["promotion_gate"] = {
        "passed": promotion_ready,
        "reasons": promotion_reasons,
        "ready_sources": ready_sources,
        "total_sources": result_count,
        "required_successful_runs": required_runs,
        "minimum_window_hours": minimum_window_hours,
    }
    report["promotion_ready"] = promotion_ready
    report.setdefault("gate", {})["promotion_ready"] = promotion_ready
    report["history"] = {
        "path": str(history_path),
        "entries": len(history),
        "candidate_set_sha256": candidate_set_sha256,
        "error": history_error,
    }
    if history_error:
        report["success"] = False
        report["ok"] = False
        report["gate_passed"] = False
        if isinstance(report.get("gate"), dict):
            report["gate"]["passed"] = False
            report["gate"]["reasons"] = (
                list(report["gate"].get("reasons") or []) + promotion_reasons
            )
    return report


@app.command(name="audit-sources")
def audit_sources_cmd(
    registry: Path | None = typer.Option(
        None,
        "--registry",
        help="Candidate JSONL registry; defaults to config.canary.registry_path.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Verified live JSONL or published Clash/sing-box baseline.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Atomic JSON audit report destination.",
    ),
    history: Path | None = typer.Option(
        None,
        "--history",
        help="Compact JSONL history used for the three-run promotion gate.",
    ),
    candidate: list[str] | None = typer.Option(
        None,
        "--candidate",
        help="Candidate id to audit; repeat the option to select multiple ids.",
    ),
    round_number: int = typer.Option(
        1,
        "--round",
        min=1,
        help="Candidate round selected when --candidate is omitted.",
    ),
    verify: bool = typer.Option(
        False,
        "--verify/--no-verify",
        help="Run the production two-tier verifier in an isolated temp snapshot.",
    ),
    max_nodes: int = typer.Option(
        0,
        "--max-nodes",
        min=0,
        help="Optional per-source cap that can only reduce registry limits.",
    ),
    max_runtime: int = typer.Option(
        0,
        "--max-runtime",
        min=0,
        help="Per-source verifier wall-clock cap; 0 uses the canary config.",
    ),
    require_promotion_ready: bool = typer.Option(
        False,
        "--require-promotion-ready/--no-require-promotion-ready",
        help="Fail unless the three-run/48-hour promotion history gate is met.",
    ),
) -> None:
    """Audit disabled source candidates without touching production snapshots."""

    console.rule("[bold cyan]audit sources")
    quality = _load_quality()
    canary_config = quality.get("canary") or {}
    registry_path = _audit_path(
        registry,
        Path(str(canary_config.get("registry_path") or "state/candidates.jsonl")),
    )
    baseline_path = _audit_path(baseline, LIVE)
    output_path = _audit_path(output, STATE / "source-audit.json")
    history_path = _audit_path(
        history,
        Path(str(canary_config.get("history_path") or DEFAULT_CANARY_HISTORY)),
    )

    try:
        source_audit.validate_artifact_paths(
            registry_path=registry_path,
            baseline_path=baseline_path,
            output_path=output_path,
            history_path=history_path,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    records = source_audit.load_candidates(registry_path)
    selected_ids = list(candidate or [])
    if not selected_ids:
        selected_ids = [
            str(record["id"])
            for record in records
            if str(record.get("candidate_round", "")) == str(round_number)
        ]
    records_by_id = {str(record.get("id")): record for record in records}
    missing_ids = sorted(set(selected_ids) - set(records_by_id))
    selected_records = [
        records_by_id[source_id]
        for source_id in selected_ids
        if source_id in records_by_id
    ]

    reasons: list[str] = []
    try:
        canary_total_cap = int(
            quality.get(
                "canary_max_total_nodes",
                canary_config.get("max_total_nodes", DEFAULT_CANARY_MAX_TOTAL_NODES),
            )
        )
        per_source_cap = int(canary_config.get("max_nodes_per_source", 250))
        required_runs = int(
            canary_config.get("required_successful_runs", DEFAULT_CANARY_REQUIRED_RUNS)
        )
        minimum_window_hours = int(
            canary_config.get("minimum_window_hours", DEFAULT_CANARY_WINDOW_HOURS)
        )
        if canary_total_cap < 1 or per_source_cap < 1 or required_runs < 1:
            raise ValueError("caps and required_successful_runs must be positive")
        if minimum_window_hours < 0:
            raise ValueError("minimum_window_hours must be non-negative")
        if str(canary_config.get("sample_strategy", "stable_hash")) != "stable_hash":
            raise ValueError("sample_strategy must be stable_hash")
        if (
            str(canary_config.get("sample_seed", STABLE_SAMPLE_SEED))
            != STABLE_SAMPLE_SEED
        ):
            raise ValueError("sample_seed does not match the parser sampling version")
        response_cap = int(
            canary_config.get("response_cap_bytes", source_audit.MAX_RESPONSE_BYTES)
        )
        fetch_timeout = float(canary_config.get("fetch_timeout_seconds", 20))
        mirror_threshold = float(canary_config.get("mirror_jaccard_minimum", 0.80))
        unsupported_limit = float(canary_config.get("max_unsupported_ratio", 0.20))
        overlap_limit = float(canary_config.get("max_overlap_ratio", 0.90))
        reject_private_reserved = canary_config.get("reject_private_reserved", True)
        configured_max_runtime = int(
            canary_config.get("candidate_max_runtime_seconds", 900)
        )
        if not isinstance(reject_private_reserved, bool):
            raise ValueError("reject_private_reserved must be boolean")
        if configured_max_runtime < 0:
            raise ValueError("candidate_max_runtime_seconds must be non-negative")
        if not 1 <= response_cap <= source_audit.MAX_RESPONSE_BYTES:
            raise ValueError("response_cap_bytes must be within 1..25 MiB")
        if fetch_timeout <= 0:
            raise ValueError("fetch_timeout_seconds must be positive")
        if not all(
            0 <= value <= 1
            for value in (mirror_threshold, unsupported_limit, overlap_limit)
        ):
            raise ValueError("ratio thresholds must be between 0 and 1")
    except (TypeError, ValueError) as exc:
        canary_total_cap = DEFAULT_CANARY_MAX_TOTAL_NODES
        per_source_cap = 250
        required_runs = DEFAULT_CANARY_REQUIRED_RUNS
        minimum_window_hours = DEFAULT_CANARY_WINDOW_HOURS
        response_cap = source_audit.MAX_RESPONSE_BYTES
        fetch_timeout = 20.0
        mirror_threshold = 0.80
        unsupported_limit = 0.20
        overlap_limit = 0.90
        reject_private_reserved = True
        configured_max_runtime = 900
        reasons.append(f"invalid canary quality configuration: {exc}")

    effective_max_runtime = max_runtime or configured_max_runtime

    effective_caps: dict[str, int] = {}
    for record in selected_records:
        source_id = str(record.get("id") or "")
        try:
            configured_value = record.get("max_nodes")
            if configured_value is None:
                configured_cap = per_source_cap
            elif isinstance(configured_value, bool) or not isinstance(
                configured_value, int
            ):
                raise ValueError("max_nodes must be an integer or null")
            else:
                configured_cap = configured_value
            if configured_cap < 1:
                raise ValueError("max_nodes must be positive")
            effective_caps[source_id] = min(
                configured_cap,
                per_source_cap,
                max_nodes or configured_cap,
            )
        except (TypeError, ValueError) as exc:
            reasons.append(f"{source_id}: invalid max_nodes: {exc}")
        if record.get("enabled") is not False:
            reasons.append(f"{source_id}: candidate must remain disabled")
        if record.get("tier") != 3:
            reasons.append(f"{source_id}: candidate tier must be 3")
        if record.get("sample_strategy") != "stable_hash":
            reasons.append(f"{source_id}: sample_strategy must be stable_hash")
        if not record.get("discovered_at"):
            reasons.append(f"{source_id}: discovered_at is required")
    planned_nodes = sum(effective_caps.values())
    if (
        missing_ids
        or not selected_records
        or planned_nodes > canary_total_cap
        or reasons
    ):
        if missing_ids:
            reasons.append("unknown candidate ids: " + ", ".join(missing_ids))
        if not selected_records:
            reasons.append(f"no candidates found for round {round_number}")
        if planned_nodes > canary_total_cap:
            reasons.append(
                f"planned candidate nodes {planned_nodes} exceed canary cap {canary_total_cap}"
            )
        summary = {
            "version": 1,
            "success": False,
            "results": [],
            "totals": {
                "candidates": len(selected_records),
                "planned_nodes": planned_nodes,
            },
            "gate": {"passed": False, "reasons": reasons},
            "error": "; ".join(reasons),
        }
        source_audit.write_report(summary, output_path)
        _print_table("source audit summary", summary["totals"] | {"success": False})
        _ensure_success("audit-sources", summary)
        return

    timeout = fetch_timeout
    max_bytes = response_cap

    def verifier_callback(nodes: list[ProxyNode], result: dict) -> dict:
        cheap_reasons: list[str] = []
        if result.get("status") != "ok":
            cheap_reasons.append(f"audit status is {result.get('status')}")
        http_status = result.get("http_status")
        if (
            isinstance(http_status, bool)
            or not isinstance(http_status, int)
            or not 200 <= http_status < 300
        ):
            cheap_reasons.append(f"fetch status {http_status!r} is not HTTP 2xx")
        unsupported_ratio = result.get("unsupported_ratio")
        if (
            isinstance(unsupported_ratio, (int, float))
            and unsupported_ratio > unsupported_limit
        ):
            cheap_reasons.append(
                f"unsupported/invalid ratio {unsupported_ratio:.3f} exceeds "
                f"{unsupported_limit:.2f}"
            )
        if (
            reject_private_reserved
            and int(result.get("private_reserved_count", 0) or 0) > 0
        ):
            cheap_reasons.append("source contains private or reserved endpoints")
        if float(result.get("overlap_ratio", 0.0) or 0.0) > overlap_limit:
            cheap_reasons.append(f"semantic overlap exceeds {overlap_limit:.2f}")
        if cheap_reasons:
            return {
                "completed": True,
                "success": False,
                "skipped": True,
                "tier1_tested": 0,
                "tier1_alive": 0,
                "tier2_tested": 0,
                "tier2_passed": 0,
                "error": "verification skipped after cheap gate: "
                + "; ".join(cheap_reasons),
            }
        eligible = [
            node for node in nodes if not source_audit._host_flags(node.host)[0]
        ]
        summary = _verify_candidate_isolated(
            eligible, max_runtime=effective_max_runtime or None
        )
        summary["private_reserved_excluded"] = len(nodes) - len(eligible)
        return summary

    report = source_audit.run(
        registry_path=registry_path,
        baseline_path=baseline_path,
        output_path=output_path,
        candidate_ids=selected_ids,
        verify=verify,
        max_nodes=max_nodes or None,
        max_nodes_per_source=per_source_cap,
        mirror_jaccard=True,
        verifier=verifier_callback if verify else None,
        timeout=timeout,
        max_bytes=max_bytes,
        exclude_private=True,
        gate_config={
            "min_net_new": 5,
            "max_overlap_ratio": overlap_limit,
            "max_private_reserved_ratio": 0.0 if reject_private_reserved else 1.0,
            "require_baseline": True,
        },
    )
    report = _apply_canary_gates(
        report,
        verify_enabled=verify,
        baseline_path=baseline_path,
        mirror_threshold=mirror_threshold,
        max_unsupported_ratio=unsupported_limit,
        max_overlap_ratio=overlap_limit,
        reject_private_reserved=reject_private_reserved,
        required_runs=required_runs,
        minimum_window_hours=minimum_window_hours,
        require_batch_diversity=(
            (round_number == 1 and not candidate) or len(selected_ids) > 1
        ),
    )
    fingerprint_records = [
        dict(record, max_nodes=effective_caps[str(record.get("id") or "")])
        for record in selected_records
    ]
    fingerprint_settings = {
        "round_number": round_number,
        "verify_enabled": bool(verify),
        "primary_only": bool(canary_config.get("primary_only", True)),
        "required_successful_runs": required_runs,
        "minimum_window_hours": minimum_window_hours,
        "mirror_jaccard_minimum": mirror_threshold,
        "max_unsupported_ratio": unsupported_limit,
        "canary_max_total_nodes": canary_total_cap,
        "sample_seed": STABLE_SAMPLE_SEED,
        "semantic_key_version": SEMANTIC_KEY_VERSION,
        "source_audit_schema_version": source_audit.AUDIT_SCHEMA_VERSION,
        "canary_history_schema_version": CANARY_HISTORY_SCHEMA_VERSION,
        "response_cap_bytes": response_cap,
        "fetch_timeout_seconds": fetch_timeout,
        "candidate_max_runtime_seconds": effective_max_runtime or None,
        "verifier_contract_version": VERIFY_PROGRESS_SCHEMA_VERSION,
        "canary_gate_version": CANARY_GATE_SCHEMA_VERSION,
        "canary_gate_contract": {
            "max_overlap_ratio": overlap_limit,
            "max_private_reserved_ratio": 0.0 if reject_private_reserved else 1.0,
            "tier1_minimum": "max(5,ceil(0.10*n))",
            "tier2_minimum": "max(5,ceil(0.05*n))",
            "net_new_tier2_minimum": 5,
            "diversity_protocols": ["hysteria2", "juicity", "ssr", "tuic"],
            "mirror_requires_primary": True,
            "reject_private_reserved": reject_private_reserved,
        },
        "clash_speedtest_version": os.environ.get("CLASH_SPEEDTEST_VERSION", "unknown"),
        "verifier_quality": {
            "max_latency_ms": quality.get("max_latency_ms", 1000),
            "min_download_speed_mbps": quality.get("min_download_speed_mbps", 5),
            "download_size_bytes": quality.get("download_size_bytes", 10485760),
            "probe_timeout_seconds": quality.get("probe_timeout_seconds", 5),
            "verifier_process_timeout_seconds": quality.get(
                "verifier_process_timeout_seconds", 30
            ),
        },
    }
    candidate_fingerprint = _candidate_set_fingerprint(
        fingerprint_records,
        fingerprint_settings,
    )
    candidate_fingerprints = {
        str(record.get("id") or ""): _candidate_set_fingerprint(
            [record], fingerprint_settings
        )
        for record in fingerprint_records
    }
    candidate_diversity_requirements = {
        str(record.get("id") or ""): record.get("candidate_round") == 1
        for record in fingerprint_records
    }
    report["canary"] = {
        "round": round_number,
        "candidate_ids": selected_ids,
        "candidate_set_sha256": candidate_fingerprint,
        "planned_nodes": planned_nodes,
        "canary_max_total_nodes": canary_total_cap,
        "max_nodes_per_source": per_source_cap,
        "sample_strategy": "stable_hash",
        "sample_seed": STABLE_SAMPLE_SEED,
        "primary_only": bool(canary_config.get("primary_only", True)),
        "batch_diversity_required": report["gate"].get(
            "batch_diversity_required", False
        ),
        "max_runtime_seconds": effective_max_runtime or None,
        "max_overlap_ratio": overlap_limit,
        "reject_private_reserved": reject_private_reserved,
        "response_cap_bytes": max_bytes,
    }
    report = _update_canary_history(
        report,
        history_path=history_path,
        candidate_set_sha256=candidate_fingerprint,
        candidate_fingerprints=candidate_fingerprints,
        candidate_diversity_requirements=candidate_diversity_requirements,
        required_runs=required_runs,
        minimum_window_hours=minimum_window_hours,
    )
    if require_promotion_ready and not report.get("promotion_ready"):
        promotion_reasons = list(
            (report.get("promotion_gate") or {}).get("reasons") or []
        )
        report["success"] = False
        report["ok"] = False
        report["gate_passed"] = False
        report["gate_reasons"] = (
            list(report.get("gate_reasons") or []) + promotion_reasons
        )
        report["error"] = "; ".join(promotion_reasons) or "promotion gate is not ready"
        if isinstance(report.get("gate"), dict):
            report["gate"]["passed"] = False
            report["gate"]["reasons"] = (
                list(report["gate"].get("reasons") or []) + promotion_reasons
            )
        if isinstance(report.get("totals"), dict):
            report["totals"]["success"] = False
            report["totals"]["ok"] = False
    source_audit.write_report(report, output_path)
    totals = report.get("totals") or {}
    summary = {
        "candidates": totals.get("candidates", 0),
        "fetched": totals.get("fetched", 0),
        "unique": totals.get("unique", 0),
        "net_new": totals.get("net_new", 0),
        "gate_passed": report.get("gate_passed", False),
        "promotion_ready": report.get("promotion_ready", False),
        "require_promotion_ready": require_promotion_ready,
        "history": report.get("history", {}).get("entries", 0),
        "output": str(output_path),
        "success": report.get("success", False),
    }
    _print_table("source audit summary", summary)
    if not report.get("success"):
        reasons = list(report.get("gate_reasons") or [])
        history_error = (report.get("history") or {}).get("error")
        if history_error:
            reasons.append(f"canary history: {history_error}")
        report["error"] = "; ".join(reasons) or "source audit gate failed"
        source_audit.write_report(report, output_path)
    _ensure_success("audit-sources", report)


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


@app.command(name="gray-crawl")
def gray_crawl_cmd() -> None:
    """G1: discover panel leads and process explicitly approved registrations."""
    console.rule("[bold cyan]gray-crawl (G1)")
    summary = gray_sources.run()
    _print_table("gray-crawl summary", summary)
    _ensure_success("gray-crawl", summary)


@app.command(name="scan-targets")
def scan_targets_cmd(
    shards: Path = typer.Option(
        scanner.SHARDS_FILE,
        "--shards",
        help="File containing one explicitly approved CIDR or IP per line.",
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        help="Comma-separated TCP ports; defaults to config/gray_sources.yaml.",
    ),
    rate: int | None = typer.Option(
        None,
        "--rate",
        min=1,
        help="Override the configured masscan packet rate.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Run despite scan.enabled=false; an explicit target file is still required.",
    ),
) -> None:
    """G2: scan explicitly listed targets and write quarantined leads."""
    parsed_ports: list[int] | None = None
    if ports:
        try:
            parsed_ports = sorted(
                {int(value.strip()) for value in ports.split(",") if value.strip()}
            )
        except ValueError as exc:
            raise typer.BadParameter("ports must be comma-separated integers") from exc
        if not parsed_ports or any(port < 1 or port > 65535 for port in parsed_ports):
            raise typer.BadParameter("ports must be between 1 and 65535")

    console.rule("[bold cyan]scan-targets (G2)")
    summary = scanner.run(
        shards_file=shards,
        ports=parsed_ports,
        rate=rate,
        enabled_override=True if force else None,
    )
    _print_table("scan-targets summary", summary)
    _ensure_success("scan-targets", summary)


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
