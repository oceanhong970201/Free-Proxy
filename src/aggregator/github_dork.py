"""GitHub/Gist secret dorking — Stage 19 / A4 (deep-gray).

Two modes:
  1. GitHub code search (REST /search/code, needs GITHUB_TOKEN env, 10/min
     code_search bucket, 1000/query cap). Third-party hits are LOGGED ONLY —
     we never fetch raw content (fetch_third_party_raw=false); notify/takedown
     is a human step.
  2. Self-org audit via trufflehog (`trufflehog github --org=<org>`) and a
     local `gitleaks dir <ROOT>` sweep with custom proxy-secret rules. Hits on
     the self org that contain vmess:// / vless:// URIs are appended to
      state/gray_nodes.jsonl as disabled, review-required JSON records.

Missing GITHUB_TOKEN -> code search skipped + logged (no crash).
Missing gitleaks/trufflehog binaries -> skipped + logged.

Run directly:  python src/aggregator/github_dork.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = ROOT / "config" / "github_dorks.yaml"
GITLEAKS_RULES = ROOT / "tools" / "gitleaks-custom.toml"
STATE_DIR = ROOT / "state"
GRAY_NODES_FILE = STATE_DIR / "gray_nodes.jsonl"
LAST_RUN_FILE = STATE_DIR / "last-run.json"

# GitHub code search: 10 req/min (code_search bucket), 1000 results/query cap.
CODE_SEARCH_BASE = "https://api.github.com/search/code"
CODE_SEARCH_RATE_GAP = 6.5  # seconds between requests (~9/min safety margin)
CODE_SEARCH_MAX_RESULTS = 1000
CODE_SEARCH_PER_PAGE = 100

# URI schemes we harvest from self-org leak findings (same set as gray_sources).
URI_RE = re.compile(
    r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>\"'#,]+)",
    re.IGNORECASE,
)


def _log(msg: str) -> None:
    print(f"[github-dork] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        _log(f"config not found: {CONFIG_FILE} — using defaults.")
        return {"dorks": [], "self_org": "", "fetch_third_party_raw": False}
    raw = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}
    return raw


# ---------------------------------------------------------------------------
# GitHub code search
# ---------------------------------------------------------------------------


def _gh_search_one(query: str, fetch_raw: bool) -> list[dict]:
    """Run one dork query via `gh api` (uses gh CLI auth, no PAT needed).

    Returns list of hit dicts. Same policy: third-party raw never fetched.
    """
    hits: list[dict] = []
    page = 1
    total_collected = 0
    rate_retries = 0
    while total_collected < CODE_SEARCH_MAX_RESULTS:
        try:
            proc = subprocess.run(
                [
                    "gh",
                    "api",
                    "-X",
                    "GET",
                    "search/code",
                    "-f",
                    f"q={query}",
                    "-f",
                    f"per_page={CODE_SEARCH_PER_PAGE}",
                    "-f",
                    f"page={page}",
                    "--jq",
                    "[.items[] | {repo:.repository.full_name, path:.path, "
                    "html_url:.html_url}] | .[]",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
            )
        except Exception as e:  # noqa: BLE001
            _log(f"  gh api failed: {type(e).__name__}: {e}")
            break
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            if "rate limit" in stderr.lower() or "403" in stderr:
                if rate_retries >= 3:
                    _log("  gh rate-limit retry budget exhausted.")
                    break
                rate_retries += 1
                _log("  gh rate-limited — pausing 60s.")
                time.sleep(60)
                continue
            _log(f"  gh api rc={proc.returncode}: {stderr[:200]}")
            break
        rate_retries = 0
        # gh --jq emits one JSON object per line for the .[] pattern
        page_hits = 0
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            hits.append({**obj, "query": query})
            page_hits += 1
            if not fetch_raw:
                _log(
                    f"  third-party hit (raw NOT fetched): {obj.get('repo')}:{obj.get('path')}"
                )
            total_collected += 1
        if page_hits < CODE_SEARCH_PER_PAGE:
            break
        page += 1
        time.sleep(CODE_SEARCH_RATE_GAP)
    return hits


def _github_search_one(
    client: httpx.Client, token: str, query: str, fetch_raw: bool
) -> list[dict]:
    """Run one dork query against /search/code. Returns list of hit dicts.

    Respects 10/min pacing + Retry-After backoff. Caps at 1000 results/query.
    Third-party hits are logged but never fetched raw (fetch_raw=false).
    """
    hits: list[dict] = []
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "free-proxy-github-dork/1.0",
    }
    page = 1
    total_collected = 0
    retries = 0
    while total_collected < CODE_SEARCH_MAX_RESULTS:
        params = {"q": query, "per_page": CODE_SEARCH_PER_PAGE, "page": page}
        try:
            r = client.get(
                CODE_SEARCH_BASE, params=params, headers=headers, timeout=20.0
            )
        except Exception as e:  # noqa: BLE001
            if retries >= 3:
                _log(f"  query request failed: {type(e).__name__}; retries exhausted")
                break
            retries += 1
            time.sleep(min(2**retries, 30))
            continue

        # Rate limit / abuse handling.
        if r.status_code == 403 or r.status_code == 429:
            if retries >= 3:
                _log("  rate-limit retry budget exhausted.")
                break
            retries += 1
            ra = r.headers.get("Retry-After")
            if ra:
                try:
                    wait = min(max(int(ra) + 1, 1), 300)
                except ValueError:
                    wait = 60
                _log(f"  rate-limited (Retry-After={wait}s) — backing off.")
                time.sleep(wait)
                continue  # retry same page
            # Secondary rate limit without Retry-After: pause and retry once.
            _log("  secondary rate limit — pausing 60s.")
            time.sleep(60)
            continue
        if 500 <= r.status_code < 600:
            if retries >= 3:
                _log(f"  query HTTP {r.status_code}; retries exhausted")
                break
            retries += 1
            time.sleep(min(2**retries, 30))
            continue
        if r.status_code != 200:
            _log(f"  query HTTP {r.status_code}")
            break
        retries = 0

        try:
            data = r.json()
        except Exception:  # noqa: BLE001
            _log("  non-JSON response — stop.")
            break

        if not isinstance(data, dict):
            _log("  JSON response had an invalid shape — stop.")
            break
        items = data.get("items", []) or []
        if not isinstance(items, list):
            _log("  JSON response items had an invalid shape — stop.")
            break
        if not items:
            break
        for it in items:
            repo = (it.get("repository") or {}).get("full_name", "")
            path = it.get("path", "")
            html_url = it.get("html_url", "")
            hits.append(
                {"repo": repo, "path": path, "html_url": html_url, "query": query}
            )
            # Third-party raw fetch is disabled by policy — we only record the
            # location for human notify/takedown, never retrieve the secret.
            if not fetch_raw:
                _log(f"  third-party hit (raw NOT fetched): {repo}:{path}")
        total_collected += len(items)
        # GitHub /search/code caps total_count at 1000. Some compatible API
        # responses omit total_count, in which case short-page pagination wins.
        try:
            advertised_total = min(
                int(data.get("total_count")), CODE_SEARCH_MAX_RESULTS
            )
        except (TypeError, ValueError):
            advertised_total = CODE_SEARCH_MAX_RESULTS
        if total_collected >= advertised_total:
            break
        if len(items) < CODE_SEARCH_PER_PAGE:
            break
        page += 1
        # Pacing: code_search bucket = 10/min.
        time.sleep(CODE_SEARCH_RATE_GAP)
    return hits


def github_code_search(cfg: dict) -> tuple[list[dict], bool]:
    """Run all dork queries. Returns (hits, skipped_no_token).

    Prefers `gh` CLI auth (no PAT needed). Falls back to httpx+GITHUB_TOKEN.
    """
    dorks = cfg.get("dorks") or []
    fetch_raw = bool(cfg.get("fetch_third_party_raw", False))
    if fetch_raw:
        _log("fetch_third_party_raw is true — overriding to false (policy).")
        fetch_raw = False
    all_hits: list[dict] = []

    # Prefer gh CLI (uses keyring auth, no PAT env needed)
    gh_bin = shutil.which("gh")
    if gh_bin:
        _log("using `gh` CLI for code search (no PAT needed).")
        for q in dorks:
            _log(f"code search dork: {q}")
            hits = _gh_search_one(q, fetch_raw)
            _log(f"  {len(hits)} hits (raw fetch disabled; logged only).")
            all_hits.extend(hits)
        return all_hits, False

    # Fallback: httpx + GITHUB_TOKEN
    token = (os.environ.get("GITHUB_TOKEN") or "").strip()
    if not token:
        _log(
            "GITHUB_TOKEN not set and gh CLI not available — skipping code search (log only)."
        )
        return [], True
    _log("gh CLI not available — using httpx + GITHUB_TOKEN.")
    with httpx.Client(follow_redirects=True) as client:
        for q in dorks:
            _log(f"code search dork: {q}")
            hits = _github_search_one(client, token, q, fetch_raw)
            _log(f"  {len(hits)} hits (raw fetch disabled; logged only).")
            all_hits.extend(hits)
    return all_hits, False


# ---------------------------------------------------------------------------
# Self-org audit (trufflehog + gitleaks)
# ---------------------------------------------------------------------------


def _run_trufflehog(self_org: str) -> list[dict]:
    """Run `trufflehog github --org=<self_org>`. Returns list of finding dicts."""
    binary = shutil.which("trufflehog")
    if not binary:
        _log("trufflehog not installed (shutil.which=None) — skipping.")
        return []
    if not self_org:
        _log("self_org empty — skipping trufflehog.")
        return []
    cmd = [binary, "github", "--org", self_org, "--json"]
    _log(f"running trufflehog: {' '.join(cmd)}")
    findings: list[dict] = []
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        _log("trufflehog timed out (300s) — partial.")
        return []
    except Exception as e:  # noqa: BLE001
        _log(f"trufflehog exec failed: {type(e).__name__}: {e}")
        return []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            f = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        findings.append(f)
    _log(f"trufflehog: {len(findings)} findings.")
    return findings


def _run_gitleaks_dir(scan_root: Path) -> list[dict]:
    """Run `gitleaks dir <root>` with custom rules. Returns finding dicts.

    Note: `detect --source` is deprecated (v8.19.0); use `dir` subcommand.
    """
    binary = shutil.which("gitleaks")
    if not binary:
        _log("gitleaks not installed (shutil.which=None) — skipping.")
        return []
    if not GITLEAKS_RULES.exists():
        _log(f"gitleaks rules missing: {GITLEAKS_RULES} — skipping.")
        return []
    with tempfile.TemporaryDirectory(prefix="gitleaks-") as temp_dir:
        report_path = Path(temp_dir) / "findings.json"
        cmd = [
            binary,
            "dir",
            str(scan_root),
            "--config",
            str(GITLEAKS_RULES),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-color",
        ]
        _log(f"running gitleaks: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            _log("gitleaks timed out (300s) — no complete report.")
            return []
        except Exception as e:  # noqa: BLE001
            _log(f"gitleaks exec failed: {type(e).__name__}")
            return []

        # Exit 1 means findings were detected. Other non-zero codes are tool
        # errors, but parse an existing complete report before returning.
        if proc.returncode not in (0, 1):
            _log(f"gitleaks exited with status {proc.returncode}.")
            return []
        if not report_path.exists():
            _log("gitleaks did not produce its JSON report.")
            return []
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _log("gitleaks report was not valid JSON.")
            return []
        if isinstance(parsed, list):
            findings = [item for item in parsed if isinstance(item, dict)]
        elif isinstance(parsed, dict):
            findings = [parsed]
        else:
            findings = []
        _log(f"gitleaks: {len(findings)} findings.")
        return findings


def _extract_uris_from_findings(findings: list[dict]) -> list[str]:
    """Pull vmess:// / vless:// URI lines out of trufflehog/gitleaks findings.

    trufflehog finding: {Finding: {Raw: "...", Redacted: ...}, ...}
    gitleaks finding:   {RuleID, Secret, Match, File, ...}
    """
    uris: list[str] = []
    for f in findings:
        # Gather candidate text blobs from both output shapes.
        blobs: list[str] = []
        if isinstance(f, dict):
            inner = f.get("Finding")
            if isinstance(inner, dict):
                blobs.append(str(inner.get("Raw") or inner.get("Redacted") or ""))
            blobs.append(str(f.get("Secret") or ""))
            blobs.append(str(f.get("Match") or ""))
            blobs.append(str(f.get("Raw") or ""))
            blobs.append(str(f.get("Line") or ""))
        for b in blobs:
            for m in URI_RE.findall(b or ""):
                uris.append(m if isinstance(m, str) else m[0])
    # Dedup preserving order.
    seen: set[str] = set()
    uniq: list[str] = []
    for u in uris:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


# ---------------------------------------------------------------------------
# State I/O
# ---------------------------------------------------------------------------


def _append_uris(uris: list[str]) -> int:
    """Append self-audit findings as fail-closed, review-required records."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if GRAY_NODES_FILE.exists():
        with GRAY_NODES_FILE.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    uri = record.get("raw") or record.get("uri")
                except Exception:  # noqa: BLE001
                    uri = line
                if isinstance(uri, str):
                    existing.add(uri)
    new = [u for u in uris if u and u not in existing]
    GRAY_NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with GRAY_NODES_FILE.open("a", encoding="utf-8") as fh:
        for u in new:
            fh.write(
                json.dumps(
                    {
                        "raw": u,
                        "uri": u,
                        "tier": "deep-gray",
                        "source_channel": "github-self-audit",
                        "enabled": False,
                        "watermark_suspect": True,
                        "review_status": "pending",
                        "ts": int(time.time()),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(new)


def _update_last_run(summary: dict) -> None:
    """Merge a 'github-dork' stage entry into state/last-run.json."""
    payload: dict = {}
    if LAST_RUN_FILE.exists():
        try:
            payload = json.loads(LAST_RUN_FILE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            payload = {}
    stages = payload.get("stages") if isinstance(payload.get("stages"), dict) else {}
    stages["github-dork"] = {"ts": int(time.time()), "counts": summary}
    payload["stages"] = stages
    payload["last_github_dork_run"] = int(time.time())
    LAST_RUN_FILE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run() -> dict:
    """Run code search + self-org audit. Returns summary dict."""
    cfg = load_config()
    summary: dict[str, Any] = {
        "dork_queries": len(cfg.get("dorks") or []),
        "code_search_hits": 0,
        "self_org_leaks": 0,
        "nodes_collected": 0,
        "skipped_no_token": False,
    }

    # 1. GitHub code search (third-party recon — never fetch raw).
    hits, skipped_no_token = github_code_search(cfg)
    summary["code_search_hits"] = len(hits)
    summary["skipped_no_token"] = skipped_no_token

    # 2. Self-org audit.
    self_org = (cfg.get("self_org") or "").strip()
    th_findings = _run_trufflehog(self_org) if self_org else []
    gl_findings = _run_gitleaks_dir(ROOT)
    all_findings = th_findings + gl_findings
    summary["self_org_leaks"] = len(all_findings)

    # 3. Extract proxy URIs from self-org findings -> gray_nodes.jsonl.
    uris = _extract_uris_from_findings(all_findings)
    added = _append_uris(uris)
    summary["nodes_collected"] = added
    _log(f"Wrote {added} new URIs to {GRAY_NODES_FILE}.")

    _update_last_run(summary)
    return summary


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
