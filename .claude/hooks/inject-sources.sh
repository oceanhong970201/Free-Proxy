#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook: inject source count + last-run status into session context.
# Uses python (portable) instead of jq — Windows machines often lack jq.

ROOT="${CLAUDE_PROJECT_DIR:-C:\\Users\\win10\\Documents\\Free-Proxy}"
SOURCES="${ROOT}/state/sources.json"
LASTRUN="${ROOT}/state/last-run.json"

python - "$SOURCES" "$LASTRUN" <<'PY'
import json, sys
src, lr = sys.argv[1], sys.argv[2]
try:
    s = json.load(open(src, encoding="utf-8"))
    src_count = len(s) if isinstance(s, (list, dict)) else 0
except Exception:
    src_count = 0
last_ts = "never"
last_stage = "none"
try:
    lrn = json.load(open(lr, encoding="utf-8"))
    last_ts = lrn.get("ts", "never")
    last_stage = lrn.get("stage", "none")
except Exception:
    pass
ctx = f"[proxy-aggregator] sources: {src_count} | last-run stage: {last_stage} @ {last_ts}"
out = {
    "hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": ctx,
        "sessionTitle": "proxy-aggregator",
    }
}
print(json.dumps(out))
PY