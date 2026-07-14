## PART C — 整合架構建議

### 文字架構圖
```
┌─────────────────────────────────────────────────────────────────────────┐
│  來源層（Sources）                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ GitHub repos │  │ TG channels │  │ Discourse/   │  │ Shodan/FOFA/│ │
│  │ raw + jsDelivr│  │ t.me/s + MTProto│ │ Discuz RSS  │  │ Censys/Quake│ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
└─────────┼──────────────────┼──────────────────┼──────────────────┼──────┘
          └──────────────────┬──────────────────┘                   │
                             ▼                                       │ (灰/深灰 被動)
┌────────────────────────────────────────────────────────────────────┐
│  Discovery Agent（B2 skills + B1 MCP）                              │
│  /deep-research + Tavily/Brave + GitHub code search + grep.app +  │
│  Sourcegraph + Wayback CDX + TGStat posts/search（付費）           │
│  → candidates.jsonl（canonical URL + content_hash dedup）         │
└────────────────────────┬───────────────────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────────────────┐
│  Crawl Worker（@source-crawler subagent）                          │
│  curl_cffi（TLS impersonate）+ httpx + GramJS/telethon + parsel    │
│  → staging.jsonl（raw URI，dedup by full URI）                     │
└────────────────────────┬───────────────────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────────────────┐
│  Parse + Normalize                                                  │
│  per-scheme parser（vmess base64-JSON / vless-trojan-hy2-tuic URI  │
│  + clash YAML / sing-box JSON）→ pydantic ProxyNode models         │
│  → dedup by (host:port:proto:cred:fingerprint)                    │
└────────────────────────┬───────────────────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────────────────┐
│  Verify Worker（@node-verifier subagent）                            │
│  one-shot mihomo per batch（clash-speedtest / mihomo-speedtest-rs）│
│  TCP→TLS→sing-box config check→HTTP-over-proxy→generate_204       │
│  → live.jsonl {uri, latency_ms, alive, country} + last-run.json   │
└────────────────────────┬───────────────────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────────────────┐
│  Convert + Serve                                                    │
│  subconverter（Docker sidecar）→ clash/sing-box/v2ray/base64       │
│  + manual typed emitters（pyyaml + pydantic）                       │
│  → D1 nodes 表 + KV 快取渲染 sub 60s                               │
│  → CF Worker /sub（base64）+ /admin/import（X-Admin-Token）         │
│  → CF Pages static shards（25 MiB/file）+ jsDelivr CDN fallback    │
│  → RSS feed（<enclosure> per region/protocol）                     │
└────────────────────────┬───────────────────────────────────────────┘
                         ▼
┌────────────────────────────────────────────────────────────────────┐
│  Schedule + Publish                                                  │
│  GitHub Actions cron（*/30，6h/job，matrix chunking）權威管線      │
│  + Deno Deploy cron heartbeat + UptimeRobot webhook                 │
│  + self-hosted cron（VPS）mihomo 子程序超 Action 上限              │
│  → GITHUB_TOKEN push 回 repo + CF Pages deploy                      │
│  + CF Worker pool（cmliu/edgetunnel 多實例）作自建節點來源        │
└────────────────────────────────────────────────────────────────────┘
```

### 關鍵流程
1. **Source discovery**（每 15 min–24h，依源）：Discovery agent 跑 GitHub code search + grep.app regex + TGStat post search + Discourse RSS + Wayback CDX，canonical URL + content_hash dedup，產 candidates.jsonl。新源 SPN-capture 至 Wayback 保命。
2. **Crawl**（每 15-30 min）：source-crawler subagent 以 curl_cffi `impersonate=chrome131` + 真實 UA（fake-useragent）fetch 各源；對 TG 用 `t.me/s/` 無登入路徑（公開頻道）或 telethon MTProto（私有/深歷史）；regex 抽 9 協議 URI；dedup by full URI 寫 staging.jsonl。
3. **Parse + Normalize**：per-scheme dispatch（vmess base64-JSON、vless/trojan/hy2/tuic URI querystring、clash YAML `proxies:`、sing-box `outbounds[]`）→ pydantic ProxyNode；round-trip 標準化後 dedup by `(host:port:proto:cred:fingerprint)`。
4. **Verify**（每 30 min–1h）：node-verifier subagent spawn one-shot mihomo per batch（clash-speedtest Go 內嵌 mihomo 最可靠跨全協議）；TCP→TLS→sing-box config load→HTTP-through-proxy `https://cp.cloudflare.com/generate_204` 兩輪間隔 45s；按中位數 HTTP 延遲排序；寫 live.jsonl + last-run.json。
5. **Convert + Serve**：subconverter Docker sidecar（自架，勿用公開 backend 洩 sub URL）產 clash/sing-box/v2ray/base64；typed manual emitters 為主；upsert D1 `nodes` 表（alive/latency/country）；KV 快取渲染 `/sub` 60s（低於 5M rows read/day）；CF Pages static shards（25 MiB/file，按區/協議分片）+ jsDelivr fallback（sub-20 MB shards）+ RSS feed（`<enclosure>` per region/protocol，`<ttl>30</ttl>`）。
6. **Schedule + Publish**：GitHub Actions cron `*/30`（權威，6h/job 以 matrix chunking + self-restarting `workflow_run` 處理）+ Deno Deploy cron heartbeat 觸發 `/sub/refresh` + UptimeRobot webhook `workflow_dispatch` + self-hosted VPS cron 跑 mihomo 子程序超 Action 上限；`GITHUB_TOKEN` push 回 repo + `cloudflare/pages-action@v1` 部署；CF Worker pool（cmliu/edgetunnel 多實例跨帳號/網域，混淆 `worker_obfuscates.js`）作自建節點來源，從 CF 外（GitHub Actions/Deno Deploy aggregator）聚合使單一 Worker 似非公開 proxy 服務。

### 推薦技術棧組合
- **Runtime**：Bun（dev）+ Node 22/undici（CI）/ Python 3.12 + asyncio（scraper daemon）
- **Fetch**：curl_cffi（load-bearing anti-bot TLS）+ httpx（async）+ cycletls（Node 指紋站）
- **Sources**：GramJS（TG 讀）+ telethon（TG MTProto）+ PyGithub/ghapi（aggregator repos）+ raw fetch Shodan/FOFA/Quake
- **Discovery**：Tavily MCP + Brave MCP + GitHub MCP code search + grep.app regex + Sourcegraph GraphQL + Wayback CDX + TGStat posts/search（付費）
- **Parse/normalize**：pyyaml + pydantic v2 ProxyNode + per-scheme dispatcher
- **Test**：clash-speedtest（Go，內嵌 mihomo，跨全協議最可靠）/ mihomo-speedtest-rs（Rust）/ 自訂 asyncio aiohttp + aiohttp-socks（健康僅）
- **Store**：D1（edge，SQL）+ KV（快取渲染 sub）/ sqlmodel + better-sqlite3（local）/ duckdb（analytics）
- **Export**：subconverter Docker sidecar（自架）+ typed manual emitters（pyyaml + pydantic / js-yaml `dump()` + TS interfaces）
- **Schedule**：GitHub Actions cron（權威）+ Deno Deploy cron（heartbeat）+ UptimeRobot webhook + self-hosted cron（mihomo 子程序）
- **CLI**：typer + rich（Py）/ commander（Node）
- **Deploy**：CF Worker `/sub` API + D1/KV + CF Pages static shards + jsDelivr CDN fallback + RSS feed + GitHub Pages（訂閱站）
- **AI harness**：Claude Code skills（/crawl、/check-nodes、/publish）+ hooks（SessionStart inject、PreToolUse deny rm -rf、PostToolUse auto-verify、Stop stale-check）+ subagents（source-crawler sonnet、node-verifier haiku）+ statusline + auto-memory；MCP essentials（fetch、Playwright、Tavily、telegram、SQLite、GitHub、Cloudflare、Memory、Time）+ custom proxy-aggregator-mcp

### 風險提示（操作層）
- **憑證洩露**：勿透過第三方 gh-proxy/ghfast 路由私有倉庫或帶 token 請求；勿用公開 subconverter backend（洩訂閱 URL）；`api_id`/`api_hash`/session file 為全帳號憑證，勿發布；CF Worker `ADMIN`/`ADMIN_TOKEN` 用 secret 非 vars；GitHub PAT 用 fine-grained + repo scope 限定。
- **TG flood/ban**：拋棄式 SIM 認證；catch `FloodWaitError` sleep `seconds+1`；`get_input_entity` 快取 + session file 持久化；多 `api_id` 分片頻道；datacenter IP 比 residential IP 早 flood wait。
- **假/蜜罐節點**：`#filembad-*`/`#ProxyMtpVPN-*`/`#canfingV2rayNG-*` tag 節點常輪 UUID 但同 IP——dedup by resolved IP 非 URI；decode vmess base64 JSON 檢 `add/host/path/sni` 再匯入；敵意 Clash YAML `rule-providers`/`script`/remote providers 為供應鏈向量——parse 至靜態 proxy list 而非餵 raw YAML 給 Clash provider fetcher；TG-MTProxy `server=...&secret=dd...` 路由 TG 流量經第三方，僅測試用非真帳號；訂閱 URL 旋換本身為攻擊（信任後換惡意端點），pin domain + 變更重驗。
- **CF ToS §2.2.1(j)**：禁 VPN/proxy；所有 Workers/Pages/Snippets VLESS 技術違反，靠混淆 + Snippets 漏洞 + 選擇性執法存活。**勿在單一 CF 帳號公開免費節點端點**——觸 1101/1103 暫停。pool 多小個人實例跨帳號/網域，從 CF 外聚合使單一 Worker 似非公開 proxy 服務。D1 5M rows read/day（2025-02-10 強制）與 KV 1k writes/day 為硬限——KV 快取 `/sub` 輸出。
- **GitHub Actions 上限**：6h/job 硬、5 分鐘 cron 最小、256 matrix、60 天 repo idle 自動停 workflow、github.com 排程高負載延遲/跳過。重驗證超 6h 拆 matrix chunk + self-restarting `workflow_run`；移至 self-hosted VPS 或 CF Worker。
- **Provider ToS**：DO/Vultr/Linode/AWS/GCP 禁 internet scanning；Shodan/FOFA/Quake ToS cap query volume + 禁 resale；TGStat paid-API credits 超額違條款；TG ToS 禁 bulk channel scraping。CF Python Workers beta 套件受限——讀路徑非 scrape 路徑。
- **雜訊/去重**：相同 sub URL 出現於 50 repos + Google + TG post；canonical URL（github.com/.../raw ↔ raw.githubusercontent.com）+ content_hash（sorted normalized node set）雙層 dedup；tombstone 死源保留供 Wayback 復活；re-fetch 比較 content_hash bump version。
- **資料 minimization**：不持久 harvestable sub tokens；aggregate 至 counts；發布資料集 redact IP；遵守刪除請求。
- **scan hygiene**：分離 user、無 shared keys、firewall research VPS、log 所有 outbound scan 供自身 audit；masscan `--rate` bounded、`-T2` polite、`--max-rate`；勿對第三方完成 login / validate leaked UUID。

---

### 優先級排序的落地清單

1. **[立即] 建Verified-node DB 與基礎爬蟲** — 用 Au1rxx/free-vpn-subscriptions 的 `output/clash.yaml`+`singbox.json`+`v2ray-base64.txt` 與 barry-far/Epodonios 的 base64 為 seed 上游（已是驗證過的最高質源）；本地 sqlmodel SQLite `nodes(host,port,protocol,country,latency_ms,alive,last_checked,source)`；`/check-nodes` skill 跑 clash-speedtest（Go 內嵌 mihomo）每 30 min。
2. **[立即] 自架 subconverter Docker sidecar + D1/KV Worker** — `docker run -d -p 25500:25500 tindy2013/subconverter:latest`；最小 D1-backed Worker（`/sub` base64 + `/admin/import` `X-Admin-Token`）；KV 快取 `/sub` 60s。勿用公開 backend。
3. **[立即] Claude Code harness** — `/init` → `/fewer-permission-prompts` → 撰 source-crawler.md + node-verifier.md subagents → `/crawl` `/check-nodes` `/publish` skills（`disable-model-invocation: true` for check/publish）→ SessionStart/PreToolUse/PostToolUse/Stop hooks + statusline.sh；MCP essentials `mcp.json`（fetch、Playwright、Tavily、telegram、SQLite、GitHub、Cloudflare、Memory、Time）。
4. **[短期] curl_cffi + regex 解析器** — `pip install curl_cffi fake-useragent parsel pydantic pyyaml`；per-scheme dispatcher（vmess base64-JSON、vless/trojan/hy2/tuic URI、clash YAML、sing-box JSON）；dedup by `(host:port:proto:cred:fingerprint)` + canonical URL + content_hash 雙層。
5. **[短期] TG 無登入爬取 + yaney01 938-handle 清單** — `t.me/s/<channel>` HTML scrape（`?before=` 分頁）+ CONFIG_RE 9 協議 regex；抓 yaney01/telegram-collector 的 `telegram channels.json`（938 handles）作 seed；拋棄式 SIM telethon MTProto 僅私有/深歷史。
6. **[短期] GitHub Actions cron `*/30` 權威管線** — fetch→parse→dedup→verify→commit→CF Pages deploy；6h/job 以 matrix chunking；CDN purge jsDelivr；`EndBug/add-and-commit@v7`/`stefanzweifel/git-auto-commit-action`。
7. **[短期] CF Pages static shards + RSS feed 服務** — 按區/協議分片（<25 MiB/file）+ jsDelivr fallback（sub-20 MB）+ RSS `<enclosure>` per region/protocol `<ttl>30</ttl>`。
8. **[中期] 自建 CF Worker pool** — fork cmliu/edgetunnel（非 zizifn 原版，避 1101）部署 N 實例跨 N CF 帳號/網域（各 UUID + KV，混淆 `worker_obfuscates.js`）；捕各 `/sub/[uuid]` 餵 aggregator 作 `ADD`/`ADDAPI`；從 CF 外聚合。
9. **[中期] Source discovery agent** — GitHub REST `/search/code` + GraphQL `search(CODE)` regex（10/min pacing）+ grep.app `regexp=true` + Sourcegraph GraphQL + TGStat `api.tgstat.ru/posts/search`（付費，免費僅自有頻道 Stat）+ Discourse `/latest.rss` + Wayback CDX-enumerate + SPN-capture 新源；canonical+content_hash dedup；candidates→promoter→sources。
10. **[中期] Shodan/FOFA/Quake 被動 recon（灰）** — `app:"V2Board"`/`app:"Xboard"` FOFA+Quake 指紋庫；CF edge JARM `07d14d16...` + 便宜 VPS ASN 交叉為 REALITY tell；`ssl.cert.subject.CN:"workers.dev"` + `body="Bad Request"` 為 Worker tell；產 leads（非攻擊目標），申請授權後才主動探測。
11. **[中期] Discourse JSON + Discuz cookie 爬取** — NodeSeek/LinuxDo/LowEndTalk `/latest.json`+`/search.json`+`stream[]`+`post_ids[]` chunks（Cloudflare UA）；HostLoc 登入重放 `<prefix>_auth`+`_saltkey` + `td.t_f`；V2EX `/api/topics/show.json?node_name=proxy`（重限流）；Discourse `/latest.rss`。
12. **[長期] custom proxy-aggregator-mcp** — `@modelcontextprotocol/sdk` TS ~100 行暴露 `fetch_subscription`/`verify`/`convert`/`dedupe_and_score`/`push_to_repo`/`deploy_to_worker`；為專案核心差異化。
13. **[長期] self-hosted VPS daemon** — Fly.io/$4 box 全 Python 棧（curl_cffi + telethon + mihomo 子程序）跑超 Action 6h 上限的重驗證；CF Python Worker（beta）讀路徑 edge-cached 零冷啟交付。
14. **[持續] 死源 tombstone + Wayback 復活** — 404/Gone 源 tombstone 保留；CDX-enumerate 網域找歷史 sibling；SPN-capture 新源保命；re-fetch 比較 content_hash bump version。

**最小可行落地（48 小時內）**：步驟 1（Au1rxx+barry-far seed → sqlmodel DB + clash-speedtest 每 30 min）+ 步驟 2（subconverter Docker + D1/KV Worker `/sub`）+ 步驟 3（Claude Code harness skills+hooks+subagents+MCP）+ 步驟 6（GitHub Actions `*/30` cron push 回 repo + CF Pages deploy）。此四步即產生一個自我更新、已驗證、三格式（clash/sing-box/v2ray）的訂閱服務；其餘為擴展來源廣度與自建節點池。