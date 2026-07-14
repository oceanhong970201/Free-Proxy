#!/usr/bin/env bash
set -euo pipefail

# statusline: live node count | source count | last-run ts
# Uses python (portable) instead of jq — Windows machines often lack jq.

ROOT="${CLAUDE_PROJECT_DIR:-C:\\Users\\win10\\Documents\\Free-Proxy}"
LIVE="${ROOT}/state/live.jsonl"
SOURCES="${ROOT}/state/sources.json"
LASTRUN="${ROOT}/state/last-run.json"

live_count=0
[[ -f "$LIVE" ]] && live_count=$(wc -l < "$LIVE" 2>/dev/null | tr -d ' ' || echo 0)

read -r src_count last_ts < <(python - "$SOURCES" "$LASTRUN" <<'PY' 2>/dev/null
import json, sys
src, lr = sys.argv[1], sys.argv[2]
try:
    s = json.load(open(src, encoding="utf-8"))
    sc = len(s) if isinstance(s, (list, dict)) else 0
except Exception:
    sc = 0
try:
    lrn = json.load(open(lr, encoding="utf-8"))
    ts = lrn.get("ts", "never")
    if ts != "never":
        ts = str(ts)
except Exception:
    ts = "never"
print(sc, ts)
PY
)
src_count="${src_count:-0}"
last_ts="${last_ts:-never}"

printf '🐳 nodes: %s | 📡 src: %s | ⏱ %s\n' "$live_count" "$src_count" "$last_ts"