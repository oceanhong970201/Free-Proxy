#!/usr/bin/env bash
set -euo pipefail

# PreToolUse hook: deny destructive rm -rf / rm -fr commands.
# Reads tool JSON from stdin. Uses python -c (portable, no jq, no heredoc conflict).

python -c '
import json, sys, re
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
cmd = (data.get("tool_input") or {}).get("command", "")
if re.search(r"rm\s+-(rf|fr)(\s|$)|rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r", cmd, re.I):
    print(json.dumps({
        "permissionDecision": "deny",
        "permissionDecisionReason": "Destructive \x27rm -rf\x27 blocked by deny-destructive.sh"
    }))
    sys.exit(0)
sys.exit(0)
'