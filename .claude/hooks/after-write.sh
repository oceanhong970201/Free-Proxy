#!/usr/bin/env bash
set -euo pipefail

# PostToolUse hook: after Write, if file is staging.jsonl auto-run parse (fast,
# updates D1 + live.jsonl); if .py file, run black -q if available.
#
# NOTE: we do NOT auto-run `verify` here — verify is a multi-hour clash-speedtest
# pass that, when spawned concurrently by repeated writes, OOM-killed the machine
# (see incident 2026-07-14). verify must be triggered explicitly via /check-nodes
# or the CI `verify-daily` workflow. A lockfile guards against concurrent parse.

ROOT="${CLAUDE_PROJECT_DIR:-C:\\Users\\win10\\Documents\\Free-Proxy}"
LOCK="${ROOT}/state/.parse.lock"

file_path="$(python -c '
import json, sys
try:
    d = json.load(sys.stdin)
    fp = (d.get("tool_input") or {}).get("file_path") or (d.get("tool_input") or {}).get("path") or ""
    print(fp)
except Exception:
    pass
')"

[[ -z "$file_path" ]] && exit 0

case "$file_path" in
  *staging.jsonl)
    # Guard: skip if another parse is already running (stale lock > 10min cleared).
    if [[ -f "$LOCK" ]]; then
      age=$(( $(date +%s) - $(stat -c %Y "$LOCK" 2>/dev/null || echo 0) ))
      if (( age < 600 )); then
        exit 0   # another parse in flight, skip
      fi
    fi
    touch "$LOCK"
    # Background parse (fast, non-blocking). Remove lock on completion.
    ( python "${ROOT}/src/aggregator/cli.py" parse >/dev/null 2>&1; rm -f "$LOCK" ) &
    ;;
  *.py)
    if command -v black >/dev/null 2>&1; then
      black -q "$file_path" >/dev/null 2>&1 || true
    fi
    ;;
esac

exit 0