---
description: Discover new upstream proxy subscription sources
allowed-tools: Bash(python *), WebSearch, WebFetch, Read, Write
---

Discover candidate upstream proxy-subscription sources (GitHub repos, raw subscription URLs, TG channels, forums) and write them deduped to `state/candidates.jsonl`.

## Behavior

1. Use **Tavily** (via `tavily_search`) and/or **WebSearch** to search for terms like:
   - `free v2ray subscription`, `clash yaml free nodes`, `sing-box config free`,
   - `vless reality subscription`, `github proxy aggregator`.
2. Use **GitHub code search** to find repos publishing `vmess://`, `vless://`, `clash.yaml`, `singbox.json`. REST endpoint `/search/code` (10/min rate) or GraphQL `search(CODE)`.
3. Fetch each candidate URL with **WebFetch** to confirm it returns parseable node URIs (cheap URL-shape filter → GET → parse body → liveness handshake optional).
4. Canonicalize each candidate URL so mirror-equivalent sources collapse:
   - `github.com/<owner>/<repo>/raw/<branch>/<path>` ↔ `raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>`
   - drop jsDelivr / gh-proxy mirror wrappers back to canonical raw form.
5. Dedup candidates by canonical URL. Write one JSON object per line to `${CLAUDE_PROJECT_DIR}/state/candidates.jsonl`:
   ```json
   {"url":"...","canonical":"...","format":"clash|v2ray|singbox","tier":3,"discovered":"<iso-ts>"}
   ```
6. (Optional) Wayback SPN-capture new sources for tombstone revival.

## Report

Report: number of new candidates found, number passing the cheap parse filter, number that are canonical-dedup duplicates of existing `state/sources.json` entries, and a shortlist of the top 5 most promising new sources for human review before promotion into `sources.json`.
