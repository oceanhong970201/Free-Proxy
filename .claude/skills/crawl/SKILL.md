---
description: Crawl proxy subscription sources into staging.jsonl
argument-hint: "[source-id-or-url]"
allowed-tools: Bash(httpx *), Bash(curl *), Read, Write, WebFetch
---

Crawl upstream proxy subscription sources listed in `state/sources.json` and write raw, parsed node URIs to `state/staging.jsonl`.

## Context (auto-injected)

Current source count in `state/sources.json`:

!`cat ${CLAUDE_PROJECT_DIR}/state/sources.json 2>/dev/null | jq length`

## Behavior

1. Read `${CLAUDE_PROJECT_DIR}/state/sources.json`. Each entry has `{id, url, format, enabled, tier, mirrors?}`.
2. If `$ARGUMENTS` is non-empty:
   - If it matches a source `id` field, fetch ONLY that source.
   - If it looks like a URL (starts with `http://` or `https://`), fetch ONLY that URL directly.
3. Otherwise, fetch ALL sources where `enabled: true`, ordered by `tier` ascending (tier 1 first).
4. For each source, fetch with `httpx` (preferred) or `curl` as fallback. Honor `mirrors[]` as fallback URLs when the primary `url` returns non-200 or times out.
5. Parse the response body with the per-scheme dispatcher and extract the 9 supported protocol URIs:
   `vmess://`, `vless://`, `trojan://`, `ss://`, `ssr://`, `tuic://`, `hysteria2://` / `hy2://`, `juicity://`.
   Regex (yaney01 pattern):
   ```
   (?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>#]+)
   ```
6. Dedup by full URI and append each unique node as a JSON line to `${CLAUDE_PROJECT_DIR}/state/staging.jsonl` using the ProxyNode schema from `_INTERFACE.md`.
7. Do NOT verify liveness — that is the job of `/check-nodes`. Just crawl + parse + write.

## Report

After running, report: number of sources attempted, number of sources OK/failed, total nodes written to `staging.jsonl`, and any dead (404/Gone) sources that should be tombstoned.
