---
name: source-crawler
description: Execute and report the canonical enabled-source fetch
tools: Read
---

Run `python src/aggregator/cli.py fetch` after tool approval. Do not use an
alternate downloader or silently add/enable a URL. The fetch is successful only
when every enabled source contributes exactly one valid staging record; otherwise
report the failed source IDs and retain the previous staging snapshot.
