---
description: Fetch the enabled source manifest into a complete staging snapshot
disable-model-invocation: true
allowed-tools: Read
---

Run `python src/aggregator/cli.py fetch` from the repository root. The checked-in
`state/sources.json` manifest is authoritative: do not bypass its enabled gate,
redirect/size limits, mirror order, or complete-snapshot requirement with curl
or a one-off downloader. A nonzero result retains the previous staging file.
