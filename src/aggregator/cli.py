"""typer + rich CLI (Stage 1).

  fetch  — sources.json -> state/staging.jsonl
  parse  — staging.jsonl -> dedup -> SQLite nodes table
  verify — clash-speedtest stub -> backfill state/live.jsonl
  emit   — live.jsonl -> output/{clash.yaml,singbox.json,v2ray-base64.txt}
  all    — fetch -> parse -> verify -> emit (CI entrypoint)

Updates state/last-run.json {stage, ts, counts} after each run.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

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

app = typer.Typer(help="Free-Proxy aggregator CLI (Stage 1).")
console = Console()


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


def _init_db() -> sqlite3.Connection:
    DB.parent.mkdir(parents=True, exist_ok=True)
    schema = (ROOT / "infra" / "d1" / "schema.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(str(DB))
    conn.executescript(schema)
    # Migration: add download_speed column to pre-existing nodes.db.
    # schema.sql already declares it for fresh DBs, but existing DBs created
    # before this change need the column added explicitly. Idempotent.
    try:
        conn.execute("ALTER TABLE nodes ADD COLUMN download_speed REAL")
    except sqlite3.OperationalError:
        pass  # column already exists
    return conn


# ---- core logic (plain callables, used by both CLI commands and `all`) ----
def _fetch_logic() -> dict:
    summary = fetcher.run()
    _write_last_run(1, {"fetch": summary}, extra={"last_stage_cmd": "fetch"})
    return summary


def _parse_logic() -> dict:
    if not STAGING.exists():
        console.print("[yellow]no staging.jsonl — skipping parse")
        summary = {"raw_nodes": 0, "unique": 0, "duplicates": 0}
        _write_last_run(1, {"parse": summary}, extra={"last_stage_cmd": "parse"})
        return summary

    sources_by_id = {s["id"]: s for s in _read_sources()}
    raw_nodes: list[ProxyNode] = []
    src_counts: dict[str, int] = {}

    for line in STAGING.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        sid = rec.get("source_id", "unknown")
        src_fmt = (
            sources_by_id.get(sid, {}).get("format")
            if sid in sources_by_id
            else "v2ray"
        )
        text = rec.get("raw") or ""
        nodes = parser.parse_raw(src_fmt, text)
        for n in nodes:
            n.source = sid
        raw_nodes.extend(nodes)
        src_counts[sid] = len(nodes)

    unique, dropped = dedupe.dedupe_nodes(raw_nodes)
    chash = dedupe.content_hash(unique)

    conn = _init_db()
    # Reset the nodes table to the current snapshot. Without this, rows from
    # dropped sources (barryfar/nomorewalls) and stale vpnsuper URIs (name
    # changes between runs create new PKs, so INSERT OR REPLACE never evicts
    # the old ones) accumulate indefinitely and pollute verify's node load +
    # the emitted live.jsonl. sources table is preserved (upserted below).
    conn.execute("DELETE FROM nodes")
    now = _now()
    for s in _read_sources():
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
                src_counts.get(s["id"], 0),
                s.get("status", "unknown"),
            ),
        )
    for n in unique:
        try:
            conn.execute(
                """INSERT INTO nodes(uri,proto,host,port,uuid,password,sni,net,country,latency_ms,alive,source,first_seen,last_checked,content_hash)
                   VALUES(?,?,?,?,?,?,?,?,NULL,NULL,NULL,?,?,?,?)
                   ON CONFLICT(uri) DO UPDATE SET
                     proto=excluded.proto, host=excluded.host, port=excluded.port,
                     uuid=excluded.uuid, password=excluded.password, sni=excluded.sni,
                     net=excluded.net, source=excluded.source,
                     last_checked=excluded.last_checked, content_hash=excluded.content_hash""",
                (
                    n.raw,
                    n.proto,
                    n.host,
                    n.port,
                    n.uuid,
                    n.password,
                    n.sni,
                    n.net,
                    n.source,
                    now,
                    now,
                    chash,
                ),
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

    LIVE.parent.mkdir(parents=True, exist_ok=True)
    with LIVE.open("w", encoding="utf-8") as f:
        for n in unique:
            d = n.model_dump()
            d.setdefault("alive", None)
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    summary = {
        "raw_nodes": len(raw_nodes),
        "unique": len(unique),
        "duplicates": len(dropped),
        "by_source": src_counts,
        "content_hash": chash,
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
    """Locate clash-speedtest.exe. Spec says C:\\Users\\user\\project\\go\\bin\\
    but the real install is C:\\Users\\win10\\go\\bin\\. Check both + PATH."""
    binary = shutil.which("clash-speedtest")
    if binary:
        return binary
    import os

    candidates = [
        os.environ.get("GOPATH", r"C:\Users\win10\go") + r"\bin\clash-speedtest.exe",
        r"C:\Users\user\project\go\bin\clash-speedtest.exe",
        r"C:\Users\win10\go\bin\clash-speedtest.exe",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
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
    """Two-tier quality screening via clash-speedtest (Go, embedded mihomo).

    Tier 1 (latency / fast mode): all nodes, --fast, batched (50/batch,
    220s/batch). Keep latency < max_latency_ms as alive, backfill latency_ms.
    Tier 2 (download mode): only Tier-1 alive nodes, no --fast, runs a 10 MB
    download per node, filters by min_download_speed_mbps. Backfills
    download_speed (MB/s). Then rewrites live.jsonl (alive first, sorted by
    download_speed desc) and D1 (alive/latency_ms/download_speed/last_checked).
    Falls back to stub (mark unverified) if binary missing.
    """
    binary = _find_speedtest_binary()
    if not binary:
        console.print(
            "[yellow]clash-speedtest not found — marking nodes unverified, skipping"
        )
    else:
        console.print(f"[green]clash-speedtest found at {binary}")

    q = _load_quality()
    max_latency_ms = int(q.get("max_latency_ms", 1000))
    min_dl_mbps = float(q.get("min_download_speed_mbps", 5))
    t1_conc = int(q.get("tier1_concurrent", 50))
    t2_conc = int(q.get("tier2_concurrent", 10))
    dl_size = int(q.get("download_size_bytes", 10485760))

    start_t = time.time()
    timed_out = False

    conn = _init_db()
    rows = conn.execute(
        "SELECT uri,proto,host,port,uuid,password,sni,net,source,alive,latency_ms,download_speed FROM nodes"
    ).fetchall()
    conn.close()

    nodes: list[ProxyNode] = []
    for r in rows:
        uri, proto, host, port, uuid_, pwd, sni, net, source, alive, lat, dl = r
        nodes.append(
            ProxyNode(
                proto=proto,
                host=host,
                port=port,
                uuid=uuid_,
                password=pwd,
                sni=sni,
                net=net,
                raw=uri,
                source=source,
                alive=bool(alive) if alive is not None else None,
                latency_ms=lat,
                download_speed=dl,
            )
        )

    # ensure clash.yaml exists (needed for name->host:port map + Tier1 batches)
    clash_path = ROOT / "output" / "clash.yaml"
    if not clash_path.exists() and binary:
        try:
            emit.emit_all()
        except Exception as e:
            console.print(f"[yellow]emit clash.yaml failed (non-blocking): {e}")

    # name -> host:port map (built across the full proxy set)
    # C1 fix: clash-speedtest outputs proxy names exactly as written in clash.yaml,
    # but emit_clash dedup-appends "-1"/"-2"/... to keep names unique. The names in
    # clash.yaml (produced by emit.emit_all) therefore ALREADY carry those suffixes,
    # and the names printed by clash-speedtest match them — so a straight name->hp
    # map works. But as a defensive fallback, if a name lookup misses we also try
    # stripping a trailing "-<digits>" suffix. Primary key is host:port (server:port),
    # the name is only a back-reference for clash-speedtest output rows.
    import re as _re

    _NAME_SUFFIX_RE = _re.compile(r"-\d+$")

    name_to_hp: dict[str, str] = {}
    # also a host:port-keyed set of all proxies for sanity checks
    all_proxies: list[dict] = []
    try:
        import yaml as _yaml

        if clash_path.exists():
            doc = _yaml.safe_load(clash_path.read_text(encoding="utf-8")) or {}
            all_proxies = doc.get("proxies", []) or []
            for p in all_proxies:
                hp = f"{p.get('server')}:{p.get('port')}"
                name_to_hp[p.get("name", "")] = hp
    except Exception as e:
        console.print(f"[yellow]load clash.yaml failed (non-blocking): {e}")

    def _lookup_hp(name: str, table: dict[str, str]) -> str | None:
        """Resolve a clash-speedtest output name to host:port.

        Try the name as-is first; if that misses, strip a trailing "-<digits>"
        dedup suffix (added by emit_clash) and retry. Returns None if unresolved.
        """
        if not name:
            return None
        hp = table.get(name)
        if hp:
            return hp
        stripped = _NAME_SUFFIX_RE.sub("", name)
        if stripped and stripped != name:
            return table.get(stripped)
        return None

    tier1_alive: dict[str, int] = {}  # host:port -> latency_ms
    tier2_speeds: dict[str, float] = {}  # host:port -> MB/s (declared early for resume)
    tier2_tested_hps: set[str] = set()  # Tier-2 tested host:ports (resume)
    reachable: set[str] = set()  # TCP-reachable host:ports (pre-filter, resume)

    # ---- resume support ----
    # A full verify of thousands of nodes can't finish inside one bash command
    # (10-min cap) or a single CI job window. Persist per-batch progress to
    # state/verify-progress.json and resume from the last completed batch on
    # the next run. The fingerprint ties progress to the current node set; a
    # fresh fetch/parse changes it and discards stale progress automatically.
    PROGRESS_FILE = STATE / "verify-progress.json"

    def _fingerprint() -> str:
        if not all_proxies:
            return "0"
        return f"{len(all_proxies)}:{all_proxies[0].get('server', '')}:{all_proxies[-1].get('server', '')}"

    resume_idx = 0
    try:
        if PROGRESS_FILE.exists():
            p = json.loads(PROGRESS_FILE.read_text(encoding="utf-8"))
            if p.get("fingerprint") == _fingerprint():
                tier1_alive = dict(p.get("tier1_alive", {}))
                tier2_speeds = dict(p.get("tier2_speeds", {}))
                tier2_tested_hps = set(p.get("tier2_tested_hps", []))
                reachable = set(p.get("reachable", []))
                resume_idx = int(p.get("tier1_idx", 0))
                console.print(
                    f"[cyan]resuming verify from T1 idx={resume_idx} "
                    f"(alive={len(tier1_alive)}, t2_speeds={len(tier2_speeds)})"
                )
            else:
                console.print("[dim]verify-progress fingerprint mismatch — fresh start")
    except Exception as e:
        console.print(f"[yellow]load verify-progress failed (non-blocking): {e}")

    def _save_progress(t1_idx: int) -> None:
        try:
            PROGRESS_FILE.write_text(
                json.dumps(
                    {
                        "fingerprint": _fingerprint(),
                        "tier1_alive": tier1_alive,
                        "tier1_idx": t1_idx,
                        "tier2_speeds": tier2_speeds,
                        "tier2_tested_hps": list(tier2_tested_hps),
                        "reachable": list(reachable),
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    if binary and all_proxies:
        # ---- TCP pre-filter: cheap connect gate before the expensive
        # clash-speedtest pass. Only runs on a fresh start (resume_idx==0 and
        # no saved reachable set); a resumed run reuses the reachable set from
        # progress so tier1_idx stays consistent with the filtered ordering. ----
        if resume_idx == 0 and not reachable:
            # bootstrap-safe import: cli.py may run bare (no parent package),
            # and src/ is already on sys.path via the module-top bootstrap.
            from aggregator import tcp_prefilter

            # Fresh start: clear stale alive/latency/speed from prior partial
            # runs so total_alive reflects ONLY this run's measurements.
            # (Without this, DB rows from earlier verifies inflate alive
            # counts and pollute the partial publish.)
            c = _init_db()
            c.execute(
                "UPDATE nodes SET alive=NULL, latency_ms=NULL, download_speed=NULL"
            )
            c.commit()
            c.close()
            for n in nodes:
                n.alive = None
                n.latency_ms = None
                n.download_speed = None
            console.print("[cyan]running TCP pre-filter (connect 443)...")
            reachable = tcp_prefilter.run(all_proxies)
            _save_progress(0)
        filtered_proxies = (
            [
                p
                for p in all_proxies
                if f"{p.get('server')}:{p.get('port')}" in reachable
            ]
            if reachable
            else list(all_proxies)
        )
        console.print(
            f"[cyan]TCP pre-filter: {len(filtered_proxies)}/{len(all_proxies)} "
            f"reachable -> Tier 1"
        )
        # ---- Tier 1: fast mode latency screening, batched ----
        console.rule("[bold cyan]Tier 1 — latency screening (fast mode)")
        BATCH1 = 50
        TIMEOUT1 = 220
        tmp1 = STATE / "_batch_t1.yaml"
        # M3: track unparsed clash-speedtest rows so a silent parse failure surfaces.
        unparsed_t1 = 0

        def _parse_t1(stdout: str) -> None:
            nonlocal unparsed_t1
            for line in (stdout or "").splitlines():
                parts = line.split("\t")
                # fast-mode row: 序号 / 节点名称 / 类型 / 延迟  (4 cols)
                if len(parts) >= 4 and parts[0].strip().endswith("."):
                    name = parts[1].strip()
                    lat = _parse_latency(parts[3])
                    hp = _lookup_hp(name, name_to_hp)
                    if not hp or lat is None:
                        unparsed_t1 += 1
                        continue
                    if lat < max_latency_ms:
                        tier1_alive[hp] = lat

        total = len(filtered_proxies)
        for i in range(resume_idx, total, BATCH1):
            if max_runtime and (time.time() - start_t) > max_runtime:
                console.print(
                    f"[yellow]max-runtime {max_runtime}s reached — pausing T1 at "
                    f"idx={i}/{total}, alive={len(tier1_alive)} (resume next run)"
                )
                timed_out = True
                break
            chunk = filtered_proxies[i : i + BATCH1]
            with tmp1.open("w", encoding="utf-8") as fh:
                _yaml.safe_dump({"proxies": chunk}, fh, allow_unicode=True)
            try:
                proc = subprocess.run(
                    [
                        binary,
                        "-c",
                        str(tmp1),
                        "-fast",
                        "-f",
                        ".+",
                        "-concurrent",
                        str(t1_conc),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT1,
                    encoding="utf-8",
                )
                _parse_t1(proc.stdout)
            except subprocess.TimeoutExpired:
                console.print(
                    f"[yellow]T1 batch {i}-{i+len(chunk)} timed out ({TIMEOUT1}s) — partial"
                )
            except Exception as e:
                console.print(f"[yellow]T1 batch {i} failed (non-blocking): {e}")
            console.print(
                f"[dim]T1 batch {i}-{i+len(chunk)}/{total} done, alive={len(tier1_alive)}"
            )
            _save_progress(i + len(chunk))
        tmp1.unlink(missing_ok=True)
        _save_progress(total)  # Tier 1 fully done
        console.print(f"[green]Tier 1 alive: {len(tier1_alive)}")
        # M3: warn on unparsed clash-speedtest rows (likely a format drift).
        if unparsed_t1:
            console.print(
                f"[yellow]WARNING: {unparsed_t1} Tier-1 speedtest rows could not be "
                "matched to a host:port — verify clash-speedtest output format / name mapping"
            )
        # M3 sanity check: tier1_alive=0 with a large node set usually means parse
        # failure rather than genuinely-dead nodes.
        if not tier1_alive and len(filtered_proxies) > 100:
            console.print(
                "[yellow]WARNING: tier1_alive=0 but >100 nodes were tested — possible "
                "clash-speedtest output parse failure (check row format)"
            )

    # apply Tier 1 to node objects
    for n in nodes:
        hp = f"{n.host}:{n.port}"
        if hp in tier1_alive:
            n.alive = True
            n.latency_ms = tier1_alive[hp]
            n.download_speed = None  # reset before Tier 2
        elif not timed_out and binary and (tier1_alive or all_proxies):
            n.alive = False
            n.latency_ms = None
            n.download_speed = None
        # timed_out: leave untested nodes alive=None so they resume next run
        # and publish (non-strict) can still ship them as unverified.

    tier2_tested = 0
    if binary and tier1_alive:
        # ---- Tier 2: download mode speed test, only alive nodes, batched ----
        console.rule("[bold cyan]Tier 2 — download speed test (download mode)")
        alive_proxies = [
            p
            for p in all_proxies
            if f"{p.get('server')}:{p.get('port')}" in tier1_alive
        ]
        # name -> host:port restricted to alive set (for Tier 2 output parsing)
        name_to_hp_t2 = {
            p.get("name", ""): f"{p.get('server')}:{p.get('port')}"
            for p in alive_proxies
        }
        clash_alive = STATE / "clash_alive.yaml"
        try:
            with clash_alive.open("w", encoding="utf-8") as fh:
                _yaml.safe_dump({"proxies": alive_proxies}, fh, allow_unicode=True)
        except Exception as e:
            console.print(f"[yellow]write clash_alive.yaml failed: {e}")

        BATCH2 = 30
        TIMEOUT2 = 300
        tmp2 = STATE / "_batch_t2.yaml"
        # M3: track unparsed Tier-2 rows too.
        unparsed_t2 = 0

        def _parse_t2(stdout: str) -> None:
            nonlocal unparsed_t2
            for line in (stdout or "").splitlines():
                parts = line.split("\t")
                # download-mode row: 序号 / 节点名称 / 类型 / 延迟 / 抖动 / 丢包率 / 下载速度 (7 cols)
                if len(parts) >= 7 and parts[0].strip().endswith("."):
                    name = parts[1].strip()
                    spd = _parse_speed(parts[6])
                    hp = _lookup_hp(name, name_to_hp_t2)
                    if not hp or spd is None:
                        unparsed_t2 += 1
                        continue
                    if spd >= min_dl_mbps:
                        tier2_speeds[hp] = spd

        total2 = len(alive_proxies)
        for i in range(0, total2, BATCH2):
            if max_runtime and (time.time() - start_t) > max_runtime:
                console.print(
                    f"[yellow]max-runtime {max_runtime}s reached — pausing T2 at "
                    f"idx={i}/{total2}, passed={len(tier2_speeds)} (resume next run)"
                )
                timed_out = True
                break
            batch = alive_proxies[i : i + BATCH2]
            # skip proxies already tested in a prior (resumed) run
            chunk = [
                p
                for p in batch
                if f"{p.get('server')}:{p.get('port')}" not in tier2_tested_hps
            ]
            tier2_tested += len(batch)
            if not chunk:
                continue
            with tmp2.open("w", encoding="utf-8") as fh:
                _yaml.safe_dump({"proxies": chunk}, fh, allow_unicode=True)
            try:
                proc = subprocess.run(
                    [
                        binary,
                        "-c",
                        str(tmp2),
                        "-speed-mode",
                        "download",
                        "-concurrent",
                        str(t2_conc),
                        "-download-size",
                        str(dl_size),
                        "-max-latency",
                        "1s",
                        "-min-download-speed",
                        str(min_dl_mbps),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT2,
                    encoding="utf-8",
                )
                _parse_t2(proc.stdout)
            except subprocess.TimeoutExpired:
                console.print(
                    f"[yellow]T2 batch {i}-{i+len(chunk)} timed out ({TIMEOUT2}s) — partial"
                )
            except Exception as e:
                console.print(f"[yellow]T2 batch {i} failed (non-blocking): {e}")
            # mark this window's proxies tested (resume skips them next run)
            for p in batch:
                tier2_tested_hps.add(f"{p.get('server')}:{p.get('port')}")
            console.print(
                f"[dim]T2 batch {i}-{i+len(batch)}/{total2} done, passed={len(tier2_speeds)}"
            )
            _save_progress(total)
        tmp2.unlink(missing_ok=True)
        console.print(
            f"[green]Tier 2 passed (>= {min_dl_mbps} MB/s): {len(tier2_speeds)}"
        )
        if unparsed_t2:
            console.print(
                f"[yellow]WARNING: {unparsed_t2} Tier-2 speedtest rows could not be "
                "matched to a host:port — verify clash-speedtest output format"
            )

    # apply Tier 2 speeds to node objects
    for n in nodes:
        hp = f"{n.host}:{n.port}"
        if hp in tier2_speeds:
            n.download_speed = tier2_speeds[hp]

    # write D1 (alive / latency_ms / download_speed / last_checked)
    conn = _init_db()
    now = _now()
    for n in nodes:
        if n.alive is not None:
            conn.execute(
                "UPDATE nodes SET alive=?, latency_ms=?, download_speed=?, last_checked=? WHERE uri=?",
                (1 if n.alive else 0, n.latency_ms, n.download_speed, now, n.raw),
            )
    conn.commit()
    conn.close()

    # write live.jsonl: alive first, sorted by download_speed desc
    LIVE.parent.mkdir(parents=True, exist_ok=True)

    def _sort_key(n: ProxyNode):
        # alive first; within alive, download_speed desc (None last);
        # tiebreak latency_ms asc.
        return (
            0 if n.alive else 1,
            -(n.download_speed or 0.0),
            n.latency_ms if n.latency_ms is not None else 10**9,
        )

    nodes_sorted = sorted(nodes, key=_sort_key)
    with LIVE.open("w", encoding="utf-8") as f:
        for n in nodes_sorted:
            if n.alive is None and n.name and "[unverified]" not in n.name:
                n.name = (n.name or "") + " [unverified]"
            f.write(json.dumps(n.model_dump(), ensure_ascii=False) + "\n")

    tier2_passed = len(tier2_speeds)
    total_alive = sum(1 for n in nodes if n.alive)
    summary = {
        "tier1_alive": len(tier1_alive),
        "tier2_tested": tier2_tested,
        "tier2_passed": tier2_passed,
        "total_alive": total_alive,
        "unverified": sum(1 for n in nodes if n.alive is None),
    }
    summary["completed"] = not timed_out
    if not timed_out:
        # verify completed fully — clear resume progress so the next run starts fresh
        try:
            (STATE / "verify-progress.json").unlink(missing_ok=True)
        except Exception:
            pass
    else:
        console.print("[yellow]verify paused (partial) — progress saved for resume")
    _write_last_run(1, {"verify": summary}, extra={"last_stage_cmd": "verify"})
    return summary


def _publish_logic(strict: bool = False) -> dict:
    """Publish top-N alive nodes (by download_speed) to the Cloudflare Worker.

    Non-strict (default, used by fetch.yml): publish alive=True + alive=None
    (unverified), exclude only alive=False (dead). This keeps the Worker fresh
    even before verify-daily runs. --strict requires alive=True + download_speed
    >= min_download_speed_mbps, used after verify for quality filtering.
    """
    import base64 as _b64

    import httpx

    q = _load_quality()
    min_dl = float(q.get("min_download_speed_mbps", 5))
    top_n = int(q.get("top_n_publish", 100))

    if not LIVE.exists():
        summary = {"published": 0, "error": "no live.jsonl"}
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    # load all nodes once; select twice (strict first, non-strict fallback)
    all_nodes: list[ProxyNode] = []
    for line in LIVE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            all_nodes.append(ProxyNode(**json.loads(line)))
        except Exception:
            continue

    def _select(strict_mode: bool) -> list[ProxyNode]:
        out: list[ProxyNode] = []
        for n in all_nodes:
            if n.alive is False:
                continue
            if n.alive is None:
                if strict_mode:
                    continue
            if strict_mode and (n.download_speed is None or n.download_speed < min_dl):
                continue
            out.append(n)
        return out

    selected = _select(strict)
    # M3 clobber-bug fix: if strict yields nothing (verify crashed / fresh
    # parse all-None), fall back to non-strict so /sub never empties.
    fell_back = False
    if not selected and strict:
        console.print(
            "[yellow]strict publish yielded 0 nodes — falling back to non-strict "
            "(verify may have failed or produced no alive nodes)"
        )
        selected = _select(False)
        fell_back = True

    dead_count = sum(1 for n in all_nodes if n.alive is False)
    none_alive_count = sum(1 for n in all_nodes if n.alive is None)
    if none_alive_count:
        console.print(
            f"[yellow]WARNING: {none_alive_count} nodes alive=None (unverified)"
        )
    if dead_count:
        console.print(f"[dim]{dead_count} nodes alive=False (dead), excluded")

    selected.sort(key=lambda n: -(n.download_speed or 0.0))
    selected = selected[:top_n]

    if not selected:
        summary = {"published": 0, "error": "no qualifying alive nodes"}
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    uris = "\n".join(n.raw for n in selected)
    payload = _b64.b64encode(uris.encode("utf-8")).decode("ascii")

    import os as _os

    base = _os.environ.get(
        "WORKER_URL", "https://proxy-sub-aggregator.proxy-aggregator.workers.dev"
    ).rstrip("/")
    worker_url = f"{base}/admin/import"
    token = _os.environ.get("ADMIN_TOKEN")
    if not token:
        console.print(
            "[red]ADMIN_TOKEN env not set — refusing to publish. Set it in GitHub "
            "Secrets (CI) or .env (local). The Worker admin token must NOT be "
            "hardcoded (repo is public)."
        )
        summary = {"published": 0, "error": "ADMIN_TOKEN env not set"}
        _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
        return summary

    try:
        resp = httpx.post(
            worker_url,
            content=payload,
            headers={
                "X-Admin-Token": token,
                "Content-Type": "text/plain",
            },
            timeout=120.0,
        )
        body = resp.text
        ok = 200 <= resp.status_code < 300
        console.print(
            f"[{'green' if ok else 'red'}]Worker import HTTP {resp.status_code}: {body[:300]}"
        )
        summary = {
            "published": len(selected),
            "http_status": resp.status_code,
            "worker_response": body[:500],
            "strict": strict,
            "fell_back_to_nonstrict": fell_back,
        }
        if not ok:
            summary["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        console.print(f"[red]publish POST failed: {e}")
        summary = {"published": 0, "error": str(e)}

    # KV cache purge (optional) — rely on 60s TTL by default; best-effort.
    try:
        subprocess.run(
            [
                "cmd",
                "/c",
                "npx",
                "wrangler",
                "kv",
                "key",
                "delete",
                "sub-render",
                "--namespace-id=a8cc252082fc4736b5e9ce897cd33f37",
            ],
            cwd=str(ROOT / "src" / "worker"),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except Exception:
        pass  # KV purge is best-effort; 60s TTL covers it

    _write_last_run(1, {"publish": summary}, extra={"last_stage_cmd": "publish"})
    return summary


# ---- typer commands ----
@app.command()
def fetch() -> None:
    """Fetch enabled sources into state/staging.jsonl."""
    console.rule("[bold cyan]fetch")
    summary = _fetch_logic()
    _print_table("fetch summary", summary)
    console.print(f"[green]done: {summary}")


@app.command()
def parse() -> None:
    """Parse staging.jsonl -> ProxyNode -> dedup -> SQLite nodes."""
    console.rule("[bold cyan]parse")
    summary = _parse_logic()
    _print_table("parse summary", summary)


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


@app.command(name="emit")
def emit_cmd() -> None:
    """Emit live.jsonl -> output/ (clash.yaml, singbox.json, v2ray-base64.txt)."""
    console.rule("[bold green]emit")
    summary = emit.emit_all()
    _write_last_run(1, {"emit": summary}, extra={"last_stage_cmd": "emit"})
    _print_table("emit summary", summary)


@app.command()
def publish(
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Only publish verified alive nodes (post-verify). Default: also publish unverified.",
    )
) -> None:
    """Publish top-N alive nodes (by download_speed) to the Cloudflare Worker."""
    console.rule("[bold magenta]publish")
    summary = _publish_logic(strict=strict)
    _print_table("publish summary", summary)


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


@app.command(name="publish-resin")
def publish_resin() -> None:
    """Publish alive + gray nodes to the local resin proxy pool."""
    console.rule("[bold magenta]publish-resin")
    summary = resin_publisher.run()
    _write_last_run(
        1, {"publish-resin": summary}, extra={"last_stage_cmd": "publish-resin"}
    )
    _print_table("resin summary", summary)


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


@app.command(name="ct-recon")
def ct_recon_cmd() -> None:
    """CT logs + passive DNS recon (Stage 16). Passive, no active probing."""
    console.rule("[bold cyan]ct-recon (CT logs + passive DNS)")
    summary = ct_recon.run()
    _write_last_run(1, {"ct-recon": summary}, extra={"last_stage_cmd": "ct-recon"})
    _print_table("ct-recon summary", summary)


@app.command(name="v2board-recon")
def v2board_recon_cmd(
    exploit: bool = typer.Option(
        False, "--exploit", help="exploit mode (ONLY self-owned/authorized targets)"
    )
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


@app.command(name="tg-recon")
def tg_recon_cmd() -> None:
    """Stage 18 (A5): TG web-preview scrape + 7-point honeytrap triage."""
    console.rule("[bold cyan]tg-recon (TG web-preview + honeytrap triage)")
    summary = tg_recon.run()
    _write_last_run(1, {"tg-recon": summary}, extra={"last_stage_cmd": "tg-recon"})
    _print_table("tg-recon summary", summary)


@app.command(name="all")
def all_cmd() -> None:
    """fetch -> parse -> verify -> emit -> publish -> publish-resin -> publish-self (CI entrypoint)."""
    console.rule("[bold magenta]all (full pipeline)")
    counts: dict[str, dict] = {}

    console.print("[bold cyan]== fetch ==")
    counts["fetch"] = _fetch_logic()
    console.print(f"  {counts['fetch']}")

    console.print("[bold cyan]== parse ==")
    counts["parse"] = _parse_logic()
    console.print(
        f"  raw={counts['parse'].get('raw_nodes')} unique={counts['parse'].get('unique')}"
    )

    console.print("[bold cyan]== verify (Tier1+Tier2) ==")
    counts["verify"] = _verify_logic()
    console.print(f"  {counts['verify']}")

    console.print("[bold cyan]== emit ==")
    counts["emit"] = emit.emit_all()
    console.print(f"  {counts['emit']}")

    console.print("[bold cyan]== publish ==")
    counts["publish"] = _publish_logic(strict=True)
    console.print(f"  {counts['publish']}")

    console.print("[bold cyan]== publish-resin ==")
    counts["publish-resin"] = resin_publisher.run()
    console.print(f"  {counts['publish-resin']}")

    console.print("[bold cyan]== publish-self ==")
    counts["publish-self"] = _publish_self_logic()
    console.print(f"  {counts['publish-self']}")

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
