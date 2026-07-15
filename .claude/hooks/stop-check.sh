#!/usr/bin/env bash
set -euo pipefail

# Stop hook: block stop if proxy nodes are stale.
#
# Freshness source priority:
#   1. CI: latest *successful* fetch-and-publish run timestamp (gh CLI).
#      This is the real source of truth — fetch+verify+publish runs on
#      GitHub Actions every 30min, NOT locally. The local last-run.json
#      goes stale because we stopped running verify locally.
#   2. Fallback: state/last-run.json ts (only if gh/CI is unreachable).
#
# Threshold: stale if no fresh source within 3600s (1h).

ROOT="${CLAUDE_PROJECT_DIR:-C:\\Users\\win10\\Documents\\Free-Proxy}"
LASTRUN="${ROOT}/state/last-run.json"

python - "$LASTRUN" "$ROOT" <<'PY'
import json, subprocess, sys, time

lr_path, root = sys.argv[1], sys.argv[2]
THRESH = 3600

def block(reason):
    print(json.dumps({"decision": "block", "reason": reason}))
    sys.exit(0)

def ci_in_flight():
    """True if a fetch-and-publish run is queued or in_progress (refresh underway)."""
    try:
        out = subprocess.run(
            ["gh", "run", "list", "--workflow=fetch-and-publish",
             "--status=in_progress", "--limit=1", "--json=status"],
            capture_output=True, text=True, timeout=25,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return False
        return bool(json.loads(out.stdout))
    except Exception:
        return False

def ci_fresh_age():
    """Return age (s) since latest successful fetch-and-publish CI run, or None."""
    try:
        out = subprocess.run(
            ["gh", "run", "list", "--workflow=fetch-and-publish", "--status=success",
             "--limit=1", "--json=createdAt"],
            capture_output=True, text=True, timeout=25,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        data = json.loads(out.stdout)
        if not data:
            return None
        created = data[0].get("createdAt")  # ISO 8601 UTC e.g. 2026-07-15T09:03:54Z
        if not created:
            return None
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return int((now - dt).total_seconds())
    except Exception:
        return None

# 1. CI freshness (primary)
# If a run is queued/in_progress, a refresh is underway — don't block.
if ci_in_flight():
    sys.exit(0)
age = ci_fresh_age()
if age is not None:
    if age <= THRESH:
        sys.exit(0)  # fresh — allow stop
    block(f"節點陳舊，CI 最新 success run 在 {age}s 前（>1h），先觸發 fetch-and-publish 或跑 /check-nodes")

# 2. Fallback: local last-run.json
try:
    lrn = json.load(open(lr_path, encoding="utf-8"))
    ts = lrn.get("ts")
    if ts is None:
        raise ValueError("no ts")
    age = int(time.time()) - int(ts)
    if age > THRESH:
        block(f"節點陳舊，先跑 /check-nodes（last-run {age}s ago，CI 不可用 fallback）")
    sys.exit(0)
except Exception:
    block("節點陳舊，先跑 /check-nodes（CI 與 last-run.json 皆不可用）")
PY
# python exit 0 with no block stdout = allow stop