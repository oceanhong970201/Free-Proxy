# 免費 Proxy 節點聚合器 — Agent 可執行 PRD

> 版本：1.0  日期：2026-07-14
> 性質：操作手冊，非概念文檔。每階段含任務、驗收、檔案路徑、指令。
> 執行者：AI agent（Claude Code + skills/hooks/subagents/MCP）+ 人類審核。
> 語言：繁體中文。所有路徑以 Windows `C:\Users\win10\Documents\Free-Proxy` 為根（記號 `$ROOT`）。
>
> **維護註記（2026-07-16）**：本檔保留早期需求與目標態，不能用來判定目前部署狀態。現行 fail-closed 行為、Worker snapshot 合約、D1 migration 順序與操作命令，以 [`STATUS.md`](STATUS.md) 與 [`../infra/DEPLOY.md`](../infra/DEPLOY.md) 為準。

---

## 0. 全域約定

### 0.1 專案根目錄結構（目標態）
```
$ROOT/
├── docs/                      # 本 PRD + 研究報告
│   ├── PRD.md                 # 本檔
│   ├── _research_report_full.md
│   └── _part_c.md
├── .claude/
│   ├── settings.json          # hooks + permissions
│   ├── mcp.json               # MCP servers
│   ├── skills/
│   │   ├── crawl/SKILL.md
│   │   ├── check-nodes/SKILL.md
│   │   ├── publish/SKILL.md
│   │   └── discover-sources/SKILL.md
│   ├── agents/
│   │   ├── source-crawler.md
│   │   └── node-verifier.md
│   ├── hooks/
│   │   ├── inject-sources.sh
│   │   ├── deny-destructive.sh
│   │   ├── after-write.sh
│   │   └── stop-check.sh
│   ├── scripts/
│   │   ├── parse.py
│   │   ├── verify.py
│   │   ├── dedupe.py
│   │   └── emit.py
│   ├── state/
│   │   ├── sources.json       # 上游源清單
│   │   ├── staging.jsonl      # 原始節點（dedup by URI）
│   │   ├── live.jsonl         # 驗活後
│   │   └── last-run.json
│   └── statusline.sh
├── src/
│   ├── aggregator/            # Python 主程式
│   │   ├── fetcher.py
│   │   ├── parser.py
│   │   ├── models.py
│   │   ├── dedupe.py
│   │   └── cli.py
│   └── worker/                # CF Worker（TS）
│       ├── sub-aggregator.ts
│       └── wrangler.toml
├── .github/workflows/
│   ├── fetch.yml              # */30 cron
│   └── deploy.yml             # CF Pages deploy
├── output/                    # 生成的訂閱（CI 產物）
│   ├── clash.yaml
│   ├── singbox.json
│   └── v2ray-base64.txt
├── infra/
│   ├── docker-compose.yml     # subconverter sidecar
│   └── d1/schema.sql
├── _current_knowledge.md      # 基線知識
└── README.md
```

### 0.2 執行原則
- **每次只跑一個階段**，跑完更新 `state/last-run.json`，人類審核後再進下一階段。
- **灰區管道（Shodan/FOFA/掃描/CF Worker pool）預設關閉**，在 `sources.json` 以 `enabled: false` 標記，人類明確開啟才跑。
- **憑證不入庫**：`api_id`/`api_hash`/session/PAT/CF token 全部走環境變數或 `.env`（gitignore）。
- **dedup 兩層**：canonical URL（sources 層）+ content_hash（節點層）。
- **驗活優先 clash-speedtest**（Go 內嵌 mihomo，跨全協議最可靠）。

### 0.3 驗收通用標準
每階段完成須滿足：
1. 該階段檔案已建立於指定路徑。
2. `python src/aggregator/cli.py <cmd>` 或對應指令能本地跑通。
3. `state/last-run.json` 已更新階段標記。
4. 無 unhandled exception，日誌寫入 `state/run-<ts>.log`。

---

## 階段 1 — 骨架 + Seed DB（淺，立即）

**目標**：建立專案骨架、種子上游清單、本地 SQLite DB、第一個能跑的驗活循環。

### 1.1 任務

1. 建立目錄結構（見 0.1）。
2. 撰 `sources.json` seed 清單，含以下高質上游（已驗證活躍）：
   ```json
   [
     {"id":"au1rxx-clash","url":"https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml","format":"clash","enabled":true,"tier":1},
     {"id":"au1rxx-singbox","url":"https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/singbox.json","format":"singbox","enabled":true,"tier":1},
     {"id":"au1rxx-v2ray","url":"https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt","format":"v2ray","enabled":true,"tier":1},
     {"id":"barryfar-base64","url":"https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_base64_Sub.txt","format":"v2ray","enabled":true,"tier":1},
     {"id":"epodonios-base64","url":"https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_base64_Sub.txt","format":"v2ray","enabled":true,"tier":1},
     {"id":"nomorewalls-meta","url":"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.meta.yml","format":"clash","enabled":true,"tier":2},
     {"id":"snakem982-pool","url":"https://raw.githubusercontent.com/snakem982/proxypool/main/config.yaml","format":"clash","enabled":true,"tier":2}
   ]
   ```
3. 每個 source 加鏡像 fallback 欄位：
   ```json
   "mirrors":[
     "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/clash.yaml",
     "https://gh-proxy.com/https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml"
   ]
   ```
4. 建 SQLite schema（`infra/d1/schema.sql` 本地共用）：
   ```sql
   CREATE TABLE IF NOT EXISTS nodes(
     id INTEGER PRIMARY KEY,
     uri TEXT NOT NULL UNIQUE,
     proto TEXT, host TEXT, port INTEGER,
     uuid TEXT, password TEXT, sni TEXT, net TEXT,
     country TEXT, latency_ms INTEGER, alive INTEGER,
     source TEXT, first_seen INTEGER, last_checked INTEGER,
     content_hash TEXT
   );
   CREATE INDEX IF NOT EXISTS idx_alive ON nodes(alive, latency_ms);
   CREATE INDEX IF NOT EXISTS idx_proto ON nodes(proto);
   CREATE TABLE IF NOT EXISTS sources(
     id TEXT PRIMARY KEY, url TEXT, format TEXT,
     enabled INTEGER, tier INTEGER, last_fetch INTEGER, last_count INTEGER, status TEXT
   );
   ```
5. 撰 `src/aggregator/cli.py`（typer），指令：`fetch`、`parse`、`verify`、`emit`、`all`。
6. 撰 `src/aggregator/models.py`（pydantic v2 `ProxyNode`）。
7. 本地裝 clash-speedtest（階段 1 只需 binary 在 PATH）。

### 1.2 驗收
- [ ] `python src/aggregator/cli.py fetch` 抓取 `sources.json` 全部 enabled 源，raw 寫入 `state/staging.jsonl`。
- [ ] `python src/aggregator/cli.py parse` 解析成 ProxyNode，dedup by URI，寫入 SQLite `nodes` 表。
- [ ] `python src/aggregator/cli.py verify` 跑 clash-speedtest，回填 `alive`/`latency_ms`。
- [ ] `state/last-run.json` 含 `stage:1` + 時間戳 + 節點計數。

### 1.3 依賴
```bash
pip install httpx pyyaml pydantic sqlmodel typer rich fake-useragent
# clash-speedtest（擇一）
go install github.com/faceair/clash-speedtest@latest
# 或下載 release binary 至 $ROOT/bin/
```

---

## 階段 2 — subconverter + D1/KV Worker（淺，立即）

**目標**：訂閱轉換後端 + edge 服務 API，產出可用的訂閱 URL。

### 2.1 任務

1. `infra/docker-compose.yml`：
   ```yaml
   services:
     subconverter:
       image: tindy2013/subconverter:latest
       ports: ["25500:25500"]
       restart: always
   ```
2. 啟動驗證：`curl http://localhost:25500/version`。
3. 撰 `src/worker/sub-aggregator.ts`（CF Worker）：
   - `GET /sub` → 從 D1 `nodes` 撈 `alive=1` ORDER BY `latency_ms`，base64 後回傳。
   - `POST /admin/import`（`X-Admin-Token` header）→ 接收 version 1 JSON snapshot；在同一 D1 batch 完成 upsert、舊 snapshot 停用與 `import_state` 更新，再驗證 counts。
   - KV 快取 `/sub` 60s。
4. `src/worker/wrangler.toml`：D1 binding `DB`、KV binding `CACHE`、cron `0 */2 * * *`。
5. 部署：`npx wrangler deploy`（需 CF token）。

### 2.2 驗收
- [ ] subconverter Docker 跑著，`/sub?target=clash&url=<base64>` 回傳 clash YAML。
- [ ] Worker 部署後 `https://<worker>.dev/sub` 回傳 base64 節點清單。
- [ ] `/admin/import` 用錯 token 回 401；正確 token 回 `ok:true`、`complete:true`、相同 `snapshot_id`，且 `imported == expected == expected_count`。
- [ ] KV 快取生效（連打 `/sub` 第二次 D1 query 數不增）。

### 2.3 注意
- **勿用公開 subconverter backend**（洩訂閱 URL 給第三方）。自架 Docker sidecar。
- D1 免費額 5M rows read/day（2025-02-10 強制）。`/sub` 必 KV 快取。
- `ADMIN_TOKEN` 用 `wrangler secret`，非 vars。

---

## 階段 3 — Claude Code harness（淺，立即）

**目標**：把 agent 變成本專案的駕駛艙——skills、hooks、subagents、MCP、statusline。

### 3.1 任務

1. `mcp.json`（見研究報告 B1 的 Windows-ready essentials）：
   - fetch、playwright、tavily、telegram-mcp、sqlite、memory、github、cloudflare、time。
2. skills（每個一份 `SKILL.md`）：
   - `crawl`：fetch sources.json 全部源 → staging.jsonl。
   - `check-nodes`：跑 verify.py，`disable-model-invocation: true`。
   - `publish`：live.jsonl → output/ → commit + push / CF Pages。
   - `discover-sources`：Tavily/Brave + GitHub code search 找新源 → candidates.jsonl。
3. subagents（`.claude/agents/`）：
   - `source-crawler.md`：sonnet，curl_cffi fetch + regex 抽取。
   - `node-verifier.md`：haiku，跑 clash-speedtest + 解析輸出。
4. hooks（`.claude/hooks/`）：
   - `inject-sources.sh`（SessionStart）：注入 source 計數 + last-run。
   - `deny-destructive.sh`（PreToolUse）：擋 `rm -rf`。
   - `after-write.sh`（PostToolUse）：寫 staging.jsonl 後自動 verify + format。
   - `stop-check.sh`（Stop）：節點陳舊（>1h）則 block。
5. `statusline.sh`：顯示 source 數 + live node 數 + last-run。
6. `.claude/settings.json`：permissions allow httpx/curl/git/python + hooks block。

### 3.2 驗收
- [ ] `/crawl` 跑完，staging.jsonl 有新節點。
- [ ] 寫 staging.jsonl 後 after-write hook 自動觸發 verify。
- [ ] `rm -rf` 被擋。
- [ ] SessionStart 注入 source 狀態。
- [ ] statusline 顯示 live node 數。

### 3.3 注意
- Windows：`npx` wrap 成 `cmd /c npx`；`uvx`/`uv` 不用 wrap。
- `check-nodes`/`publish` 設 `disable-model-invocation: true`，避免 AI 自誤觸發。
- telegram-mcp 需 `api_id`/`api_hash`/`session_string`（my.telegram.org/apps 取）。

---

## 階段 4 — 解析器 + 雙層 dedup（短期）

**目標**：支援全 9 協議解析 + 標準化 + 兩層去重。

### 4.1 任務

1. `src/aggregator/parser.py` per-scheme dispatcher：
   - vmess：base64-decode `raw[8:]` + JSON parse（欄 `v/ps/add/port/id/aid/net/type/host/path/tls/sni`）。
   - vless/trojan/tuic/hysteria2/ss/ssr：URI querystring parse。
   - clash YAML：PyYAML 讀 `proxies:` 段。
   - sing-box JSON：讀 `outbounds[]`。
2. 標準化：parse → reserialize（避免 base64 body 與 JSON 欄序造成假非重複）。
3. `src/aggregator/dedupe.py`：
   - Level 1（sources 層）：canonical URL（`github.com/.../raw` ↔ `raw.githubusercontent.com`）。
   - Level 2（節點層）：`(host:port:proto:cred:fingerprint)`。
   - content_hash：`sha256(sorted normalized node set)`，捕鏡像 sub。
4. 正則（yaney01 模式）：
   ```python
   CONFIG_RE = re.compile(r"(?<![\w-])((?:vmess|vless|trojan|ss|ssr|tuic|hysteria2?|hy2|juicity)://[^\s<>#]+)", re.I)
   ```

### 4.2 驗收
- [ ] 9 協議各丟一個樣本 URI，parser 回傳正確 ProxyNode。
- [ ] 同 URI 不同 base64 編碼被 dedup 視為重複。
- [ ] 鏡像 sub（`a.com/sub` vs `b.com/sub` 內容相同）被 content_hash 連結。
- [ ] dead source（404）tombstone，保留供 Wayback 復活。

### 4.3 依賴
```bash
pip install curl_cffi fake-useragent parsel pydantic pyyaml
```

---

## 階段 5 — TG 無登入爬取（短期）

**目標**：抓 TG 頻道節點，擴大來源。

### 5.1 任務

1. 抓 yaney01/telegram-collector 的 `telegram channels.json`（938 handles）作 seed，存 `state/tg-channels.json`。
2. `src/aggregator/tg_scraper.py`：
   - 無登入：`httpx.get('https://t.me/s/<channel>?before=<id>')` + BeautifulSoup `tgme_widget_message_text`。
   - regex 抽 9 協議 URI。
   - 分頁走 `?before=<mid>`，每頁 sleep 1s。
3. 偵測關閉 web preview 的頻道（空頁）→ skip。
4. （選用，灰）Telethon MTProto：拋棄式 SIM，catch `FloodWaitError` sleep `seconds+1`，`get_input_entity` 快取。

### 5.2 驗收
- [ ] 至少 5 個 TG 頻道抓到節點，寫入 staging.jsonl。
- [ ] FloodWait 正確處理（sleep 後 retry）。
- [ ] 關閉 preview 的頻道被 skip 不崩。

### 5.3 seed 頻道（手動確認活躍後入列）
- `ShareCentrePro`、`kjgxZY`、`dns68`、`V2RayRootFree`、`v2ray_free_conf`、`go4sharing`、`dljdfx`、`ccbaohe`

---

## 階段 6 — GitHub Actions 權威管線（短期）

**目標**：CI 自動跑 fetch→parse→dedup→verify→commit→deploy。

### 6.1 任務

1. `.github/workflows/fetch.yml`：
   ```yaml
   on:
     schedule: [{cron: '*/30 * * * *'}]
     workflow_dispatch:
   jobs:
     aggregate:
       runs-on: ubuntu-latest
       timeout-minutes: 30
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with: {python-version: '3.12'}
         - run: pip install httpx pyyaml pydantic sqlmodel curl_cffi fake-useragent
         - run: python src/aggregator/cli.py all
         - run: python src/aggregator/cli.py emit
         - uses: EndBug/add-and-commit@v7
           with: {message: "auto update $(date -u)", default_author: github_actions}
         - uses: cloudflare/pages-action@v1
           with: {apiToken: '${{secrets.CF_API_TOKEN}}', accountId: '${{secrets.CF_ACCOUNT_ID}}', projectName: proxy-aggregator}
   ```
2. 6h/job 上限處理：matrix chunking（拆來源成多個 job 並行）+ `workflow_run` self-restarting。
3. jsDelivr CDN purge：commit 後 `curl -X PURGE https://cdn.jsdelivr.net/gh/...`。
4. Secrets：`CF_API_TOKEN`、`CF_ACCOUNT_ID`、`GITHUB_TOKEN`（自動）、`TELEGRAM_API_ID/HASH`（若用 MTProto）。

### 6.2 驗收
- [ ] 每 30 min commit 一筆更新到 repo。
- [ ] CF Pages 部署成功，`*.pages.dev` 可下載訂閱。
- [ ] jsDelivr CDN purge 後立即反映新內容。
- [ ] 6h 上限不觸發（matrix 拆分）。

### 6.3 注意
- github.com 排程 workflow 高負載時延遲/跳過，不保證準時。
- repo 60 天無活動後自動停 workflow——定期 commit 保活。
- 公開倉免費分鐘，私有倉計費。

---

## 階段 7 — CF Pages shards + RSS 服務（短期）

**目標**：用戶面分發層，分片避 25 MiB 上限，RSS 訂閱。

### 7.1 任務

1. `src/aggregator/emit.py` 分片邏輯：
   - 按區（US/EU/JP/KR/HK/SG）+ 按協議（vmess/vless/trojan/ss/hy2/tuic）分片。
   - 每檔 < 25 MiB（CF Pages）/ < 20 MiB（jsDelivr）。
2. RSS feed：`output/feed.xml`，每 `<item>` 一個分片，`<enclosure url type length/>`，`<ttl>30</ttl>`。
3. CF Pages `_headers`：`Cache-Control: no-cache` for `/sub*`。
4. 自訂網域（選用）。

### 7.2 驗收
- [ ] 分片檔全部 < 25 MiB。
- [ ] RSS feed valid，podcast 客戶端能訂閱 auto-refresh。
- [ ] jsDelivr fallback 對 sub-20MB 分片可用。

---

## 階段 8 — 自建 CF Worker pool（中期，灰）

**目標**：自建 VLESS 節點混入聚合，零成本帶寬。

### 8.1 任務

1. Fork **cmliu/edgetunnel**（非 zizifn 原版，避 Error 1101）。
2. 部署 N 實例跨 N CF 帳號/網域（各 UUID + KV，混淆 `worker_obfuscates.js`）。
3. 捕各 `https://<domain>/sub/[uuid]` 訂閱 URL，作 `ADD`/`ADDAPI` 餵 aggregator。
4. 從 CF 外（GitHub Actions 或 Deno Deploy）聚合，使單一 Worker 似非公開 proxy 服務。

### 8.2 驗收
- [ ] 至少 3 個 edgetunnel 實例跑著，各產 VLESS 節點。
- [ ] 這些節點混入 live.jsonl 並通過驗活。
- [ ] 無單一帳號觸發 1101/1103。

### 8.3 注意（灰，操作層）
- **CF ToS §2.2.1(j) 禁 VPN/proxy**。所有部署技術上違反，靠混淆 + 選擇性執法存活。
- **勿在單一 CF 帳號公開免費節點端點**。
- CF-Workers-SUB 已 2026-06-30 archived，用 MiSub 或 edgetunnel 內建 sub。
- Snippets 玩法（2025-11）：Free plan 不可用，Pro 25/Business 50/Enterprise 300。

---

## 階段 9 — Source discovery agent（中期）

**目標**：自動發現新上游源，不再依賴手動 seed。

### 9.1 任務

1. `discover-sources` skill：Tavily + Brave + GitHub code search + grep.app + Sourcegraph + TGStat + Wayback CDX。
2. canonical URL + content_hash dedup → `candidates.jsonl`。
3. cheap→expensive validation：URL-shape filter → HEAD/GET → parse body → liveness handshake（可選昂貴）。
4. Wayback SPN-capture 新源保命。
5. 排程：github 15min、grep 15min、sourcegraph 30min、google 1h、telegram 2h、rss 10min、wayback 24h。

### 9.2 驗收
- [ ] 每週至少發現 5 個新可 parse 源。
- [ ] candidates → promoter → sources 流程跑通。
- [ ] 死源 tombstone 後 Wayback 復活成功一次。

### 9.3 注意
- GitHub code search：REST `/search/code` 10/min（code_search bucket）+ 1000/query cap；GraphQL `search(CODE)` regex。
- grep.app：`regexp=true`，1-2 req/s 禮貌。
- TGStat：`api.tgstat.ru/posts/search` 付費，免費僅自有頻道 Stat。
- Bing Web Search API legacy 2023 停新客戶。

---

## 階段 10 — Shodan/FOFA 被動 recon（中期，灰）

**目標**：產 leads（非攻擊目標），申請授權後才主動探測。

### 10.1 任務

1. `sources.json` 加 `enabled:false` 的 recon 源：
   - FOFA `app:"V2Board"` / `app:"Xboard"`。
   - Quake `app:"V2Board"` / `app:"Xboard"` / `app:"sing-box"`。
   - Shodan `ssl.cert.subject.CN:"workers.dev"` + `body="Bad Request"`。
   - REALITY tell：TLS JARM 匹配 CDN 但 host 在 VPS ASN。
2. leads 寫入 `state/recon-leads.jsonl`，**不自動探測**，人工審核。
3. 授權後才跑主動探測（ss-rpc-shooter / sing-box test）。

### 10.2 驗收
- [ ] recon-leads.jsonl 有 leads，每條標記來源 + JARM/ASN。
- [ ] 無自動主動探測發生。

### 10.3 注意（灰）
- Shodan/FOFA/Quake ToS cap query volume + 禁 resale。
- DO/Vultr/Linode/AWS/GCP 禁 internet scanning，掃描用專用 research VPS。
- Xboard magic-link/token leak（V2Board ≥1.6.1–1.7.4 已修；Xboard v0.1.9+ 未修）—僅 recon，不利用。

---

## 階段 11 — 論壇爬取（中期）

**目標**：Discourse + Discuz + V2EX 節點分享。

### 11.1 任務

1. Discourse（NodeSeek/LinuxDo/LowEndTalk）：
   - `/latest.json` + `/search.json?q=免费节点 OR 白嫖 OR 订阅` → topic id → `/t/<id>.json` `stream[]` → `/t/<id>/posts.json?post_ids[]=...` 20-ID 一批 → `cooked` HTML regex。
   - Cloudflare UA + cookie。
2. Discuz（HostLoc）：
   - 登入重放 `<prefix>_auth`+`_saltkey`，crawl `forumdisplay.php?fid=<board>&page=N` → `viewthread.php?tid=<tid>` → `td.t_f`。
   - Cloudflare backoff。
3. V2EX：
   - `/api/topics/show.json?node_name=proxy` + `node_name=vps` + `/api/replies/show.json?topic_id=<tid>`，重限流 120 req/hr。
4. Discourse `/latest.rss` 增量。

### 11.2 驗收
- [ ] 至少 3 個論壇抓到節點或白嫖碼。
- [ ] Cloudflare 403 有 backoff 處理。
- [ ] HostLoc cookie 重放成功。

### 11.3 注意
- NodeSeek `/latest.json` 匿名 WebFetch 403，需真實瀏覽器 UA + cookie。
- LinuxDo TL2+ 信任等級才能看部分帖 `posts_stream`。
- HostLoc 正規禁止直接貼節點，多為「PM me」或外連。

---

## 階段 12 — custom proxy-aggregator-mcp（長期）

**目標**：專案核心差異化，自建 MCP 暴露聚合操作。

### 12.1 任務

1. `src/mcp/proxy-aggregator-mcp.ts`（`@modelcontextprotocol/sdk`）~100 行：
   - `discover_sources(query)`
   - `fetch_subscription(url)`
   - `verify(node, {test_url, timeout, concurrency})`
   - `convert(nodes, format)` → clash|v2ray|sing-box|plain
   - `dedupe_and_score(nodes)`
   - `push_to_repo(nodes, format)`（via GitHub MCP）
   - `deploy_to_worker(nodes)`（via Cloudflare MCP）
2. 棧於 essentials：fetch + Playwright + Tavily/Brave + telegram + GitHub + Cloudflare + SQLite/Memory + Time。
3. `mcp.json` 加 `proxy-aggregator` 條目。

### 12.2 驗收
- [ ] MCP 跑著，Claude 能呼叫 `fetch_subscription` 並回傳節點。
- [ ] `verify` 跑通，回傳 alive/latency。
- [ ] `convert` 產出三格式。

---

## 階段 13 — self-hosted VPS daemon（長期）

**目標**：跑超 GitHub Actions 6h 上限的重驗證 + mihomo 子程序。

### 13.1 任務

1. Fly.io / $4 VPS，全 Python 棧（curl_cffi + telethon + mihomo 子程序）。
2. systemd timer/cron 跑 `cli.py all` 每 30 min。
3. 輸出 push 到 CF Pages + GitHub repo。
4. 防火牆隔離 research user，log 所有 outbound scan 供自身 audit。

### 13.2 驗收
- [ ] daemon 連跑 24h 無崩。
- [ ] mihomo 子程序正確 spawn + cleanup。
- [ ] 輸出與 CI 一致。

---

## 階段 14 — 死源 tombstone + Wayback 復活（持續）

**目標**：源生命週期管理。

### 14.1 任務

1. 404/Gone 源 tombstone（保留記錄，不刪）。
2. CDX-enumerate 網域找歷史 sibling。
3. SPN-capture 新源至 Wayback 保命。
4. re-fetch 比較 content_hash，bump version。

### 14.2 驗收
- [ ] 死源標 `status:tombstoned`，不 fetch 但保留。
- [ ] Wayback CDX 找回至少 1 個死源的歷史 snapshot。
- [ ] content_hash 變更觸發 version bump。

---

## 最小可行落地（48 小時）

**四步即產生自我更新、已驗證、三格式訂閱服務：**

1. **階段 1**：Au1rxx + barry-far seed → SQLite DB + clash-speedtest 每 30 min。
2. **階段 2**：subconverter Docker + D1/KV Worker `/sub`。
3. **階段 3**：Claude Code harness（skills + hooks + subagents + MCP）。
4. **階段 6**：GitHub Actions `*/30` cron push + CF Pages deploy。

其餘階段為擴展來源廣度 + 自建節點池 + discovery 自動化。

---

## 階段 15 — A7 自有節點池（self-owned，合法）【白】

**目標**：合法租用 VPS 自架 mihomo/xray，產自有節點混入訂閱，品質最穩。

### 15.1 任務
1. `src/aggregator/self_nodes.py`：
   - 讀 `config/self_nodes.yaml`（自有 VPS 清單：host/port/uuid/password/protocol）
   - 用 `node_to_uri` 重建 URI
   - 寫 `state/self_nodes.jsonl`（每行一個 URI，`tier:"self"`, `enabled:true`）
2. `config/self_nodes.yaml` seed（範例格式，人工填入自有 VPS）：
   ```yaml
   nodes:
     - proto: vless
       host: your-vps.example.com
       port: 443
       uuid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
       sni: your-vps.example.com
       net: ws
       path: /vless
       flow: xtls-rprx-vision
   ```
3. cli.py 加 `publish-self` 指令：倒 self_nodes 進 resin + Worker。
4. `all` 指令加 `publish-self` 步驟。

### 15.2 驗收
- [ ] `self_nodes.yaml` 範例格式正確
- [ ] `publish-self` 把自有節點倒進 resin subscription "self-owned"
- [ ] self_nodes.jsonl 格式正確

### 15.3 依賴
- 合法租用的 VPS（Cloudzy/Hetzner/Vultr），自架 mihomo

---

## 階段 16 — A8 CT logs + passive DNS recon（被動，合法）【白】

**目標**：用 Certificate Transparency + passive DNS 被動 enumerate proxy backend，不碰目標。

### 16.1 任務
1. `src/aggregator/ct_recon.py`：
   - `crt.sh` 查詢：`https://crt.sh/?q=<domain>&output=json`，列舉子網域/SNI
   - SecurityTrails API（env `SECURITYTRAILS_API_KEY`，可選）：歷史 A record
   - 結果寫 `state/recon_intel.jsonl`（每行 {domain, ip, sni, source, first_seen}）
   - 餵階段 17（A2 fingerprint）當前級
2. `config/ct_watch.yaml`：watch 關鍵字（airport domain、`*.workers.dev`、已知 proxy SNI）
3. cli.py 加 `ct-recon` 指令。

### 16.2 驗收
- [ ] `crt.sh` 查詢能跑（無 key 也行）
- [ ] recon_intel.jsonl 格式正確
- [ ] 無 API key 不崩

---

## 階段 17 — A2 V2Board/Xboard recon（fingerprint + exploit 雙管）【深灰→黑】

**目標**：對 V2Board/Xboard 面板做 fingerprint（403 oracle）+ 對自有/授權面板做 exploit（CVE-2026-39912 chain）。

### 17.1 任務
1. `src/aggregator/v2board_recon.py`：
   - **recon mode（預設）**：`/api/v1/admin/config/fetch` 403 oracle + `/api/v1/guest/comm/config` fingerprint 確認 panel 型別版本。只產 leads 寫 `state/recon-leads.jsonl`。
   - **exploit mode（`--exploit` flag，人工啟用）**：對 `config/v2board_targets.yaml` 列出的**自有/授權**面板跑 CVE-2026-39912 chain：
     - POST `/api/v1/passport/auth/loginWithMailLink` {email} → 取 response.data 的 verify token
     - GET `/api/v1/passport/auth/token2Login?verify=<token>` → 取 auth_data bearer
     - GET `/api/v1/user/getSubscribe` → 取 subscribe_url
     - fetch subscribe_url → 解析節點 URI
   - 節點寫 `state/gray_nodes.jsonl`（`tier:"black"`, `source_channel:"A2"`, `enabled:false` 預設，蜜罐 triage 後人工 enable）
2. `config/v2board_targets.yaml`：目標面板清單（**只列自有/授權**，預設空）
3. cli.py 加 `v2board-recon` 指令（預設 recon，`--exploit` 才 exploit）。

### 17.2 CVE chain（已驗證）
```
CVE-2026-39912 (CVSS 9.1): loginWithMailLink 回傳 magic link in body
預設 APP_KEY base64:PZXk5vTu... → admin path 144b73d9 (hash crc32b)
admin@demo.com 預設（Xboard 安裝文件建議）
```

### 17.3 驗收
- [ ] recon mode 對 mock panel 回 403/200 正確分類
- [ ] exploit mode 對自有測試面板跑通 chain
- [ ] 無目標（targets 空）不跑
- [ ] 節點寫 gray_nodes.jsonl 含 provenance 欄位

### 17.4 風險（操作層）
- 只對自有/授權面板 exploit
- 野外 panel 只 recon fingerprint，不發 magic-link
- 蜜罐識別：per-account watermark token、provenance forward graph

---

## 階段 18 — A5 TG 地下市場 recon（web-preview + 蜜罐 triage）【深灰】

**目標**：爬 TG 公共頻道找節點 URI / 網盤連結 / subconverter URL，蜜罐 triage 後才 enable。

### 18.1 任務
1. `src/aggregator/tg_recon.py`：
   - 無登入：`httpx.get('https://t.me/s/<channel>?before=<id>')` + BeautifulSoup `tgme_widget_message_text`
   - regex 抓 URI（vmess/vless/trojan/ss/ssr/tuic/hy2）+ 網盤（mega.nz/terabox）+ subconverter URL
   - **蜜罐 triage 7 點**（見研究報告 A5 §7）：
     1. watermark token 檢測
     2. provenance forward graph 多樣性
     3. hosting domain（panel vs subconverter/網盤）
     4. TTL（真洩輪替後停，蜜罐永不死）
     5. client-coupling
     6. 永不第三方 subconverter 驗證
     7. urlclash-converter 本機檢視
   - 結果寫 `state/gray_nodes.jsonl`（`tier:"deep-gray"`, `enabled:false`, `watermark_suspect:bool`）
2. `config/tg_channels.yaml`：seed 頻道清單（`jichangtj`/`buliang00`/`ccbaohe` 等）
3. cli.py 加 `tg-recon` 指令。

### 18.2 驗收
- [ ] `t.me/s/` 無登入爬取能跑
- [ ] 蜜罐 triage 7 點實作
- [ ] 節點寫 gray_nodes.jsonl 含 watermark_suspect 欄位
- [ ] 頻道關閉 web preview 被 skip

---

## 階段 19 — A4 GitHub/Gist secret dorking（自有 org 稽核 + recon）【深灰】

**目標**：GitHub code search + trufflehog/gitleaks 找洩漏的訂閱 token / UUID / APP_KEY。

### 19.1 任務
1. `src/aggregator/github_dork.py`：
   - GitHub code search API（`gh api /search/code`，需 `GITHUB_TOKEN` env，10/min code_search bucket）
   - dorks：`subscribe?token=`、`vmess://`、`uuid:`、`APP_KEY base64:PZXk`、`getSubscribe`
   - 自有 org 稽核：`trufflehog github --org=<org>` + `gitleaks dir <path>`（修正：非 `detect --source`）
   - 自訂 regex 規則覆蓋 vmess/vless UUID、subscribe token
   - 命中第三方 token：notify repo owner，**不 fetch raw、不保留 token**
   - 自有 org 命中：寫 `state/gray_nodes.jsonl`
2. `config/github_dorks.yaml`：dork 清單 + 自有 org 名
3. cli.py 加 `github-dork` 指令。

### 19.2 驗收
- [ ] 無 GITHUB_TOKEN 時只跑 gitleaks 本地掃描
- [ ] code search 10/min pacing
- [ ] 第三方 token 不 fetch raw
- [ ] 自有 org 命中寫 gray_nodes.jsonl

### 19.3 風險
- 第三方 token：notify + takedown，不使用
- 自有 org：pre-commit hook + CI 防再洩漏

---

## 階段 20 — 修 verifier D1 持久化 bug（audit C1/M1/m7）【白】

**目標**：修 audit 發現的 verifier 沒正確寫 D1 + ss SIP002 解析 + content_hash 排除 download_speed。

### 20.1 任務
1. **C1 修復**：`_verify_logic` Tier1/2 name mapping 改用 host:port 直接索引（不靠 emit 的 dedup 後綴名）。clash.yaml name→host:port map 要處理 `-1`/`-2` 後綴（regex 去後綴再查）。
2. **M1 修復**：`parser._parse_query_uri` 對 ss/ssr SIP002 userinfo base64 decode + 拆 method:password。
3. **m7 修復**：`dedupe.normalize_node` 排除 `download_speed` 欄位。
4. **C2 決策**：publish 在 alive=None 時是否發布——決定 keep strict（只 alive=True）或 mirror emit（None 也發布）。傾向 strict + log warning。
5. 加「未解析列」計數器 + 警告（M3）。

### 20.2 驗收
- [ ] 跑 verify 後 D1 `alive`/`latency_ms`/`download_speed` 非 NULL
- [ ] ss URI round-trip 正確（method 不丟）
- [ ] content_hash verify 前後一致
- [ ] publish 在有 alive 節點時發布 > 0

---

## 灰黑管道整合進既有架構

```
[既有] fetch(GitHub raw) → parse → verify → emit → publish(Worker) → publish-resin(resin)
[新增] self_nodes(階段15) → merge
[新增] ct_recon(階段16) → recon_intel.jsonl → 餵階段17前級
[新增] v2board_recon(階段17) → gray_nodes.jsonl
[新增] tg_recon(階段18) → gray_nodes.jsonl
[新增] github_dork(階段19) → gray_nodes.jsonl
[整合] gray_nodes.jsonl + self_nodes.jsonl → publish-resin 統一倒 resin
```

所有灰/黑管道預設 `enabled:false`，蜜罐 triage 後人工 enable。節點統一進 `state/gray_nodes.jsonl`，publish-resin 讀它倒進 resin。

---

## 附錄 A — 風險提示（操作層，非道德）

| 風險 | 對策 |
|---|---|
| 憑證洩露 | 勿透過第三方代理路由私有倉庫或帶 token 請求；`api_id`/`api_hash`/session 不發布；CF `ADMIN_TOKEN` 用 secret；PAT fine-grained + repo scope 限定 |
| TG flood/ban | 拋棄式 SIM；catch `FloodWaitError` sleep `seconds+1`；`get_input_entity` 快取 + session file；多 `api_id` 分片 |
| 假/蜜罐節點 | `#filembad-*` tag 節點常輪 UUID 同 IP——dedup by resolved IP；decode vmess base64 JSON 檢 `add/host/path/sni`；敵意 Clash YAML `rule-providers`/`script` 為供應鏈向量——parse 至靜態 list，勿餵 raw YAML 給 provider fetcher |
| CF ToS §2.2.1(j) | 禁 VPN/proxy；勿在單一帳號公開端點；pool 多小實例跨帳號；D1 5M rows/day + KV 1k writes/day 硬限 |
| GitHub Actions 上限 | 6h/job、5min cron min、256 matrix、60 天 idle 停；拆 matrix + `workflow_run` |
| Provider ToS | DO/Vultr/Linode/AWS/GCP 禁 scanning；Shodan/FOFA/Quake cap query + 禁 resale；TG 禁 bulk scraping |
| 雜訊/去重 | canonical URL + content_hash 雙層；tombstone 死源；re-fetch 比較 hash |
| scan hygiene | 分離 user、無 shared keys、firewall VPS、log outbound scan；`--rate` bounded；勿對第三方完成 login / validate leaked UUID |

## 附錄 B — 驗活/速度工具

| 工具 | 語言 | core | 安裝 |
|---|---|---|---|
| faceair/clash-speedtest | Go | 內嵌 mihomo | `go install github.com/faceair/clash-speedtest@latest` |
| KodeBarinn/mihomo-speedtest-rs | Rust | spawn mihomo | `cargo install mihomo-speedtest-rs` |
| mihomo | Go | Clash-core | release binary |
| sing-box | Go | `experimental.clash_api` | release binary |
| subconverter | C++ | 訂閱轉換 | `docker run tindy2013/subconverter:latest` |

## 附錄 C — 協議端口表

| 協議 | TCP | UDP | 備註 |
|---|---|---|---|
| ss | 8388,8389,8080,443 | — | AEAD，無 banner |
| ssr | 8388,80,443 | — | 無 banner |
| vmess | 8080,2052,2082,2086,2095,443,2053,2083,2087,2096,8443 | — | WS+TLS 背 nginx/CDN |
| vless+reality | 443,8443,2053 | — | 443 強烈偏好 |
| trojan | 443,8443,2053 | — | 包成 HTTPS |
| hysteria2 | — | 443,8443,4443,36712 | HTTP/3，ALPN h3 |
| tuic | — | 443,8443 | QUIC v5 |
| wireguard | — | 51820,51821 | UDP |

## 附錄 D — 上游源 tier

| Tier | Repo | 用途 |
|---|---|---|
| 1 | Au1rxx/free-vpn-subscriptions | 金標準，三格式，已驗活 |
| 1 | barry-far/V2ray-config | 最大量 base64 |
| 1 | Epodonios/v2ray-configs | 5 分鐘更新 |
| 2 | peasoft/NoMoreWalls | clash meta，中國向 |
| 2 | snakem982/proxypool | Go spider 經典 |
| 2 | wzdnzd/aggregator | 最完整爬蟲平台 |
| 2 | mahdibland/V2RayAggregator | clash YAML + 機場（注意維護狀態） |
| 3 | YawStar/Proxy-Hunter | sing-box/xray configs |
| 3 | NiREvil/vless | v2ray+clash meta+warp |
| 3 | 0xRadikal/Free-v2ray-Configs | 全協議 |

## 附錄 E — 已死/應避開

- mahdibland/V2RayAggregator（自標維護中，輸出實在 ShadowsocksAggregator/SSAggregator）
- codingbox/Free-Node-Merge（末次 2021-12）
- henson/proxypool（末次 2023-09）
- mihomo-purity/mihomo-purity（2025-02 關閉）
- cmliu/CF-Workers-SUB（2026-06-30 archived，用 MiSub）
- zizifn/edgetunnel（新部署 Error 1101，用 cmliu fork）
- freeproxy.cc（parked）
- free-ss.site（自簽憑證斷）
- v2rayfree.eu.org（2023-03 後休眠）
- DarkWebInformer/telegram-scraper（虛構，用 th3unkn0n/TeleGram-Scraper）
- diegosouzapw/OmniRoute v3.8.37（relay 產生器壞）
- GHTorrent（~2020 停維護）
- Bing Web Search API（legacy 2023 停新客戶）
