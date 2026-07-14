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

import json
import os
import re
import time
from pathlib import Path

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
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/history/{domain}"

# crt.sh `name_value` may contain multiple newline-separated SANs and a
# leading wildcard; split + clean into individual hostnames.
_HOST_RE = re.compile(r"^[a-zA-Z0-9_*-][a-zA-Z0-9.*-]+$")


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
    for part in (name_value or "").splitlines():
        part = part.strip().lower()
        if not part or not _HOST_RE.match(part):
            continue
        # drop wildcard prefix
        if part.startswith("*."):
            part = part[2:]
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
            CRTSH_URL.format(domain=domain),
            headers={"User-Agent": "free-proxy-aggregator/1.0"},
            timeout=45.0,
            follow_redirects=True,
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
        try:
            first_seen = int(ts) if ts is not None else int(time.time())
        except (TypeError, ValueError):
            first_seen = int(time.time())
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
            SECURITYTRAILS_URL.format(domain=domain),
            headers={"APIKEY": api_key},
            timeout=45.0,
            follow_redirects=True,
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
    seen: set[tuple[str, str, str]] = set()
    for rec in data.get("records") or []:
        if not isinstance(rec, dict):
            continue
        ip = rec.get("ip") or rec.get("value")
        for entry in rec.get("organizations") or []:
            if not isinstance(entry, dict):
                continue
        seen_flag_key = (domain, str(ip), str(rec.get("first_seen") or ""))
        if not ip:
            continue
        try:
            first_seen = int(rec.get("first_seen") or 0) or int(time.time())
        except (TypeError, ValueError):
            first_seen = int(time.time())
        key = (domain, str(ip), str(first_seen))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "domain": domain,
                "subdomain": domain,
                "ip": str(ip),
                "sni": domain,
                "source": "securitytrails",
                "first_seen": first_seen,
            }
        )
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
    seen: set[tuple] = set()

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
                continue
            seen.add(key)
            all_records.append(rec)
            count += 1
        per_domain[d] = {
            "crtsh_records": len(crt),
            "securitytrails_records": len(st),
            "unique_written": count,
        }

    STATE.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for rec in all_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return {
        "watch_domains": domains,
        "total_records": len(all_records),
        "per_domain": per_domain,
        "path": str(OUT),
    }


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
