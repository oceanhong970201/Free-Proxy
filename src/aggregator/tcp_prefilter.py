"""Async TCP-443 pre-filter — cheap liveness gate before clash-speedtest.

clash-speedtest's Tier-1 (mihomo handshake) is ~1-2s/node and the engine has
per-proxy overhead, so screening thousands of mostly-dead free-proxy nodes
through it wastes the bulk of a verify run on nodes whose port isn't even
open. This module does a raw TCP connect to each node's host:port with a
short timeout and high concurrency — ~50x faster per node — and returns only
the host:port set that actually accepted a connection. The downstream verify
then feeds clash-speedtest just that reachable set.

No TLS, no protocol handshake, no credential use — only "did the kernel
accept() the SYN". A trojan/vless server that doesn't even open 443 is dead
regardless of credentials; one that does MIGHT be alive and is worth the
expensive clash-speedtest pass.

Run directly:  python src/aggregator/tcp_prefilter.py   (tests state/live.jsonl)
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIVE_FILE = ROOT / "state" / "live.jsonl"

# High concurrency: a TCP connect with 3s timeout is cheap; the bottleneck is
# the round-trip, so we can fan out wide. 200 keeps us well under any sane
# ephemeral-port limit and lets the slow tail finish inside the timeout.
CONCURRENCY = 200
CONNECT_TIMEOUT = 3.0  # seconds per node


def _log(msg: str) -> None:
    print(f"[tcp-prefilter] {msg}", flush=True)


async def _check_one(host: str, port: int) -> tuple[str, int, bool]:
    """Open a TCP connection to host:port. Return (host, port, reachable)."""
    try:
        fut = asyncio.open_connection(host, port, ssl=False)
        reader, writer = await asyncio.wait_for(fut, timeout=CONNECT_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return host, port, True
    except Exception:
        return host, port, False


async def prefilter(nodes: list[dict]) -> set[str]:
    """Given node dicts (each with host+port), return reachable host:port set.

    `nodes` items may be ProxyNode-like dicts (have .host/.port) or clash
    proxy dicts (have .server/.port) — accept both.
    """
    targets: list[tuple[str, int]] = []
    for n in nodes:
        if isinstance(n, dict):
            host = n.get("host") or n.get("server") or ""
            port = n.get("port")
        else:
            host = getattr(n, "host", None) or ""
            port = getattr(n, "port", None)
        if not host or not port:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue
        targets.append((host, port))

    if not targets:
        return set()

    sem = asyncio.Semaphore(CONCURRENCY)
    reachable: set[str] = set()
    done = 0
    total = len(targets)

    async def bounded(h: str, p: int) -> tuple[str, int, bool]:
        async with sem:
            return await _check_one(h, p)

    # Stream results as they complete so the progress log shows real counts
    # (the old version read `reachable` mid-flight while gather hadn't returned).
    tasks = [asyncio.ensure_future(bounded(h, p)) for h, p in targets]
    for fut in asyncio.as_completed(tasks):
        h, p, ok = await fut
        if ok:
            reachable.add(f"{h}:{p}")
        done += 1
        if done % 200 == 0 or done == total:
            _log(f"  {done}/{total} checked, reachable={len(reachable)}")
    _log(f"done: {len(reachable)}/{total} reachable on TCP")
    return reachable


def run(nodes: list[dict] | None = None) -> set[str]:
    """Sync entrypoint. If nodes is None, load from state/live.jsonl."""
    if nodes is None:
        nodes = []
        if LIVE_FILE.exists():
            for line in LIVE_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    nodes.append(json.loads(line))
                except Exception:
                    continue
    return asyncio.run(prefilter(nodes))


if __name__ == "__main__":
    t0 = time.time()
    r = run()
    print(json.dumps({"reachable": len(r), "elapsed_s": round(time.time() - t0, 1)}))
