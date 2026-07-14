#!/usr/bin/env bash
set -euo pipefail

# Stop hook: if last-run.json ts (epoch seconds) is older than 3600s, block stop
# and ask to run /check-nodes. Uses python (portable) instead of jq + date -d.

ROOT="${CLAUDE_PROJECT_DIR:-C:\\Users\\win10\\Documents\\Free-Proxy}"
LASTRUN="${ROOT}/state/last-run.json"

python - "$LASTRUN" <<'PY'
import json, sys, time
lr = sys.argv[1]
try:
    lrn = json.load(open(lr, encoding="utf-8"))
    ts = lrn.get("ts")
    if ts is None:
        raise ValueError("no ts")
    age = int(time.time()) - int(ts)
    if age > 3600:
        print(json.dumps({"decision": "block", "reason": f"節點陳舊，先跑 /check-nodes（last-run {age}s ago）"}))
        sys.exit(0)
except Exception:
    print(json.dumps({"decision": "block", "reason": "節點陳舊，先跑 /check-nodes（last-run.json 不可用）"}))
    sys.exit(0)
# fresh — exit clean, no block
PY
# python exit 0 with no stdout block = allow stop