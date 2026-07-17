"""CT logs + passive DNS recon (Stage 16 — A8, passive/legal).

Passively enumerates proxy-backend subdomains/SNIs via Certificate
Transparency logs (crt.sh, no API key required) and historical A records via
SecurityTrails (optional, env `SECURITYTRAILS_API_KEY`). No active probing of
targets — output is a lead source feeding Stage 17 (V2Board/Xboard
fingerprint).

Config (`config/ct_watch.yaml`):
  watch_domains: [example.com, workers.dev]
  crtsh_concurrency: 5
  securitytrails_api_key: ${SECURITYTRAILS_API_KEY}  # optional

Output (`state/recon_intel.jsonl`): one JSON object per line, shape:
  {domain, subdomain, ip, sni, source, first_seen}

Public API:
  query_crtsh(domain)            -> list[dict]
  query_securitytrails(domain)   -> list[dict]
  run()                          -> summary dict
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
import yaml

# Bootstrap (mirrors cli.py / self_nodes.py pattern).
if __package__ is None or "" in __name__.split("."):
    _SRC = Path(__file__).resolve().parents[1]
    import sys

    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "ct_watch.yaml"
STATE = ROOT / "state"
OUT = STATE / "recon_intel.jsonl"

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/a"

# crt.sh `name_value` may contain multiple newline-separated SANs and a
# leading wildcard; split + clean into individual hostnames.
_HOST_RE = re.compile(r"^[a-zA-Z0-9_*-][a-zA-Z0-9.*-]+$")


def _to_epoch(value: object) -> int:
    """Normalize API integer or ISO-8601 timestamps to epoch seconds."""
    if isinstance(value, (int, float)):
        numeric = int(value)
        return numeric // 1000 if numeric > 10_000_000_000 else numeric
    text = str(value or "").strip()
    if text.isdigit():
        numeric = int(text)
        return numeric // 1000 if numeric > 10_000_000_000 else numeric
    if text:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
        except ValueError:
            pass
    return int(time.time())


def _load_config() -> dict:
    """Load config/ct_watch.yaml with ${ENV_VAR} interpolation. Returns {} if
    the file is missing (so a fresh checkout runs crt.sh on the built-in
    workers.dev default rather than crashing)."""
    if not CONFIG.exists():
        return {"watch_domains": ["workers.dev"], "crtsh_concurrency": 5}
    try:
        raw = CONFIG.read_text(encoding="utf-8")
    except Exception:
        return {"watch_domains": ["workers.dev"], "crtsh_concurrency": 5}

    def _env_sub(m: re.Match) -> str:
        return os.environ.get(m.group(1), m.group(0))

    interpolated = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", _env_sub, raw)
    try:
        doc = yaml.safe_load(interpolated) or {}
    except Exception:
        return {"watch_domains": ["workers.dev"], "crtsh_concurrency": 5}
    if not isinstance(doc, dict):
        return {"watch_domains": ["workers.dev"], "crtsh_concurrency": 5}
    return doc


def _expand_name_value(name_value: str, domain: str) -> list[str]:
    """crt.sh `name_value` can hold newline-joined SANs and `*.wild` entries.
    Expand to a deduped list of bare hostnames (wildcards stripped)."""
    out: list[str] = []
    seen: set[str] = set()
    parent = domain.strip().lower().removeprefix("*.").rstrip(".")
    for part in (name_value or "").splitlines():
        part = part.strip().lower()
        if not part or not _HOST_RE.match(part):
            continue
        # drop wildcard prefix
        if part.startswith("*."):
            part = part[2:]
        # A certificate returned for the query can contain unrelated SANs.
        # Keep only the watched parent and its actual subdomains.
        if part != parent and not part.endswith(f".{parent}"):
            continue
        if not part or part in seen:
            continue
        seen.add(part)
        out.append(part)
    return out


def query_crtsh(domain: str) -> list[dict]:
    """Query crt.sh for `domain`, return recon intel records.

    Each cert row's `name_value` is expanded into one record per SAN. Fields:
      {domain, subdomain, ip:null, sni, source:"crt.sh", first_seen}
    `ip` is null here (crt.sh is SAN-only); historical A records come from
    query_securitytrails. `first_seen` is the cert's `entry_timestamp` (UTC
    ms epoch) when present, else the current epoch.

    Never raises — network/parse failures yield [].
    """
    records: list[dict] = []
    try:
        r = httpx.get(
            CRTSH_URL.format(domain=quote(domain, safe=".*")),
            headers={"User-Agent": "free-proxy-aggregator/1.0"},
            timeout=45.0,
            follow_redirects=False,
        )
    except Exception:
        return []
    if r.status_code != 200:
        return []
    try:
        certs = r.json()
    except Exception:
        return []
    if not isinstance(certs, list):
        return []

    seen_sni: set[tuple[str, str]] = set()
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        nv = cert.get("name_value") or ""
        ts = cert.get("entry_timestamp")
        first_seen = _to_epoch(ts)
        for sni in _expand_name_value(str(nv), domain):
            key = (domain, sni)
            if key in seen_sni:
                continue
            seen_sni.add(key)
            records.append(
                {
                    "domain": domain,
                    "subdomain": sni,
                    "ip": None,
                    "sni": sni,
                    "source": "crt.sh",
                    "first_seen": first_seen,
                }
            )
    return records


def query_securitytrails(domain: str) -> list[dict]:
    """Query SecurityTrails historical A records for `domain`.

    Requires SECURITYTRAILS_API_KEY (or config securitytrails_api_key). If no
    key is present, returns [] without raising (per PRD §16.2 "no API key no
    crash"). Each historical A record yields one record with the IP filled.
    """
    api_key = os.environ.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        cfg = _load_config()
        ck = cfg.get("securitytrails_api_key")
        if isinstance(ck, str) and ck and not ck.startswith("${"):
            api_key = ck
    if not api_key:
        return []

    try:
        r = httpx.get(
            SECURITYTRAILS_URL.format(domain=quote(domain, safe="")),
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=45.0,
            # Never forward the APIKEY header to a redirect destination.
            follow_redirects=False,
        )
    except Exception:
        return []
    if r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    records: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for rec in data.get("records") or []:
        if not isinstance(rec, dict):
            continue
        values = rec.get("values") or []
        ips: list[str] = []
        direct = rec.get("ip") or rec.get("value")
        if direct:
            ips.append(str(direct))
        for value in values:
            if isinstance(value, dict):
                ip = value.get("ip") or value.get("value")
            else:
                ip = value
            if ip:
                ips.append(str(ip))
        first_seen = _to_epoch(rec.get("first_seen"))
        for ip in ips:
            try:
                # SecurityTrails DNS/A history should never produce hostnames.
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            key = (domain, ip, first_seen)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "domain": domain,
                    "subdomain": domain,
                    "ip": ip,
                    "sni": domain,
                    "source": "securitytrails",
                    "first_seen": first_seen,
                }
            )
    return records


def _record_key(record: dict) -> tuple[object, ...] | None:
    """Return the stable identity used to merge prior and fresh intelligence."""
    required = ("domain", "subdomain", "sni", "source")
    if not all(
        isinstance(record.get(field), str) and record[field] for field in required
    ):
        return None
    return (
        record["domain"],
        record["subdomain"],
        record.get("ip"),
        record["sni"],
        record["source"],
    )


def _load_existing_records() -> list[dict]:
    """Read valid prior rows; a truncated/corrupt line cannot abort a run."""
    if not OUT.exists():
        return []
    records: list[dict] = []
    try:
        lines = OUT.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        if isinstance(record, dict) and _record_key(record) is not None:
            records.append(record)
    return records


def run() -> dict:
    """Default entry: for each watch_domain, run crt.sh (+ SecurityTrails if
    key present), write all records to state/recon_intel.jsonl, return summary.

    Records are deduped by (domain, subdomain, ip, sni, source) before write.
    """
    cfg = _load_config()
    domains = cfg.get("watch_domains") or ["workers.dev"]
    if not isinstance(domains, list):
        domains = ["workers.dev"]
    domains = [str(d) for d in domains if d]

    all_records: list[dict] = []
    per_domain: dict[str, dict] = {}
    seen: dict[tuple, int] = {}

    for d in domains:
        crt = query_crtsh(d)
        st = query_securitytrails(d)
        merged = crt + st
        count = 0
        for rec in merged:
            key = (
                rec["domain"],
                rec["subdomain"],
                rec.get("ip"),
                rec["sni"],
                rec["source"],
            )
            if key in seen:
                idx = seen[key]
                all_records[idx]["first_seen"] = min(
                    _to_epoch(all_records[idx].get("first_seen")),
                    _to_epoch(rec.get("first_seen")),
                )
                continue
            seen[key] = len(all_records)
            all_records.append(rec)
            count += 1
        per_domain[d] = {
            "crtsh_records": len(crt),
            "securitytrails_records": len(st),
            "unique_written": count,
        }

    STATE.mkdir(parents=True, exist_ok=True)
    preserve_existing = cfg.get("preserve_existing", True) is not False
    previous = _load_existing_records() if preserve_existing else []
    if not all_records and OUT.exists() and preserve_existing:
        return {
            "watch_domains": domains,
            "total_records": len(previous),
            "records_written": 0,
            "new_records": 0,
            "per_domain": per_domain,
            "path": str(OUT),
            "preserved_previous": True,
        }

    # CT and passive-DNS calls can fail independently. Merge with the last
    # successful snapshot so a partial outage never erases prior intelligence.
    merged: dict[tuple[object, ...], dict] = {}
    previous_keys: set[tuple[object, ...]] = set()
    for record in previous:
        key = _record_key(record)
        if key is not None:
            previous_keys.add(key)
            merged[key] = record
    for record in all_records:
        key = _record_key(record)
        if key is None:
            continue
        old = merged.get(key)
        if old is not None:
            # Preserve the earliest observation when APIs revise their window.
            record = dict(record)
            record["first_seen"] = min(
                _to_epoch(old.get("first_seen")),
                _to_epoch(record.get("first_seen")),
            )
        merged[key] = record
    final_records = list(merged.values())

    tmp = OUT.with_suffix(OUT.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for rec in final_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    tmp.replace(OUT)

    return {
        "watch_domains": domains,
        "total_records": len(final_records),
        "records_written": len(final_records),
        "new_records": sum(1 for key in merged if key not in previous_keys),
        "per_domain": per_domain,
        "path": str(OUT),
        "preserved_previous": bool(previous),
    }


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
