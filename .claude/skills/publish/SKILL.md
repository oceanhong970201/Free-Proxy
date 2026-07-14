---
description: Publish live nodes to output subscriptions and push to repo
disable-model-invocation: true
allowed-tools: Bash(git *), Bash(curl *), Bash(python *), Read, Write
---

Publish verified live nodes from `state/live.jsonl` into the three subscription formats under `output/`, then commit + push (or POST to `$PUBLISH_ENDPOINT`) and update `state/last-run.json`.

## Behavior

1. Read `${CLAUDE_PROJECT_DIR}/state/live.jsonl`. If empty, abort with a clear message and suggest running `/check-nodes`.
2. Emit subscription files:
   !`python ${CLAUDE_PROJECT_DIR}/src/aggregator/cli.py emit`
   This writes `output/clash.yaml`, `output/singbox.json`, `output/v2ray-base64.txt`.
3. If `$PUBLISH_ENDPOINT` is set, POST the `output/` payload to it:
   ```
   curl -sS -X POST "$PUBLISH_ENDPOINT" -H "Content-Type: application/json" \
     --data-binary @${CLAUDE_PROJECT_DIR}/output/singbox.json
   ```
   Otherwise commit + push to the repo:
   ```
   git -C ${CLAUDE_PROJECT_DIR} add output/
   git -C ${CLAUDE_PROJECT_DIR} commit -m "auto: publish live nodes $(date -u +%FT%TZ)"
   git -C ${CLAUDE_PROJECT_DIR} push
   ```
4. Update `${CLAUDE_PROJECT_DIR}/state/last-run.json` with the current stage (`publish`), ISO timestamp, and live-node count. Use `jq` to merge in place.

## Report

Report: number of live nodes published, output file sizes, push/POST success status, and the new `last-run.json` timestamp.
