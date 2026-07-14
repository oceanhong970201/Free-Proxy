---
name: check-nodes
description: Verify liveness of staged proxy nodes via clash-speedtest
disable-model-invocation: true
allowed-tools: Bash(python *), Bash(${CLAUDE_PROJECT_DIR}/.claude/scripts/verify.py *), Read, Write
shell: bash
---

Run node verification (liveness + latency) against `state/staging.jsonl` and produce `state/live.jsonl` plus a backfill into `nodes.db`.

## Behavior

Run the verifier:

!`python ${CLAUDE_PROJECT_DIR}/src/aggregator/cli.py verify`

Then show the live node count:

!`wc -l < ${CLAUDE_PROJECT_DIR}/state/live.jsonl`

## Report

Summarize:
- total staged nodes (staging.jsonl line count)
- live count (live.jsonl line count)
- dead count (staged − live)
- median latency in ms (from the verifier output / nodes.db)
- any protocol with zero survivors (worth flagging for source-quality review)
