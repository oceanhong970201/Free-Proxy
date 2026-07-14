# 你需要填入的東西 — 完整清單

> 照著做就行。每項都標了：**值長什樣**、**去哪拿**、**填到哪**、**要不要填**。
> 不想全部做也行——下面分「最小可行（必填）」和「擴展（選填）」。

---

## A. 最小可行（必填，不填就跑不起來）

這 4 個是讓 CI + 訂閱服務跑起來的最小集合。**Telegram 和 Worker 暫時可以跳過**，先讓訂閱產出能更新。

### A1. `GITHUB_PAT` — GitHub Personal Access Token

- **值長什樣**：`ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`（40 字元，`ghp_` 開頭）
- **去哪拿**：
  1. 開 https://github.com/settings/tokens?type=beta（fine-grained，推薦）
  2. 點 "Generate new token"
  3. Repository access → 選你要 push 訂閱的那個 repo（或 All）
  4. Permissions → Repository permissions：
     - **Contents**: Read and write（commit/push output/）
     - **Metadata**: Read-only（自動勾）
     - **Workflows**: Read and write（如果 workflow 檔也要 push）
  5. Generate → 複製（只顯示一次）
- **填到哪**：GitHub repo Settings → Secrets and variables → Actions → New repository secret
  - Name: `GITHUB_PAT`（但其實 CI commit 用的是內建 `GITHUB_TOKEN`，這個 PAT 是給 Worker 或其他工具用。**若只用 Actions 自動 commit，這個可省**）
- **要不要填**：⚠️ **可省**——GitHub Actions 自動有 `GITHUB_TOKEN`，commit output 不需 PAT。除非你要 Worker 從外部 push 回 repo 才需要。

### A2. `CF_API_TOKEN` — Cloudflare API Token

- **值長什樣**：隨機 40 字元字串（不是 `ghp_` 開頭）
- **去哪拿**：
  1. 開 https://dash.cloudflare.com/profile/api-tokens
  2. Create Token
  3. 用 "Edit Cloudflare Pages" 模板，或自訂：
     - **Account → Cloudflare Pages → Edit**（部署 Pages）
     - **Zone → Zone → Read**（若用自訂網域）
  4. Continue → Create Token → 複製
- **填到哪**：GitHub repo Settings → Secrets → Actions → `CF_API_TOKEN`
- **要不要填**：✅ **必填**（CI 要部署 CF Pages）

### A3. `CF_ACCOUNT_ID` — Cloudflare 帳號 ID

- **值長什樣**：32 字元 hex（`xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`）
- **去哪拿**：
  1. 開 https://dash.cloudflare.com
  2. 右側欄或首頁任意 site → 右下 "Account ID"（或 dash 右上你的帳號 → Account ID）
  3. 複製
- **填到哪**：GitHub repo Settings → Secrets → Actions → `CF_ACCOUNT_ID`
- **要不要填**：✅ **必填**（Pages 部署要）

### A4. `CF_PROJECT_NAME` — Cloudflare Pages 專案名

- **值長什樣**：你自己取的字串，例如 `proxy-aggregator`
- **去哪拿**：你自己決定。但要先在 CF 建立：
  1. dash → Pages → Create a project → Connect to Git（或 Direct upload）
  2. Project name 填 `proxy-aggregator`（記住這個名字）
  3. Build output directory: `output`
  4. Save
- **填到哪**：GitHub repo Settings → Secrets → Actions → `CF_PROJECT_NAME` = `proxy-aggregator`
- **要不要填**：✅ **必填**

---

## B. Telegram（擴展，選填）

**現在可以全跳過**——階段 5 才用 TG，沒 TG 也能從 GitHub raw 源跑聚合。要擴源到 TG 頻道時再回來填。

### B1. `TELEGRAM_API_ID` — Telegram API ID

- **值長什樣**：純數字（例如 `1234567`）
- **去哪拿**：
  1. 開 https://my.telegram.org/apps（用你的 Telegram 帳號登入）
  2. Create new application
  3. App title 隨便填、Platform 選 Desktop
  4. 建好後看到 `App api_id`（數字）+ `App api_hash`（字串）
- **填到哪**：GitHub repo Secrets → `TELEGRAM_API_ID`
- **要不要填**：⏸ **選填**（階段 5 TG 爬取才需要；無登入 `t.me/s/` 爬取不需 api_id）

### B2. `TELEGRAM_API_HASH` — Telegram API Hash

- **值長什樣**：32 字元 hex（`abcdef0123456789abcdef0123456789`）
- **去哪拿**：同 B1，建 app 後 `App api_hash`
- **填到哪**：GitHub repo Secrets → `TELEGRAM_API_HASH`
- **要不要填**：⏸ **選填**

### B3. `TELEGRAM_SESSION_STRING` — Telethon session 字串

- **值長什樣**：長字串（`1xxxxx...`，幾百字元）
- **去哪拿**：
  1. 本地跑 session 產生器：
     ```bash
     pip install telethon
     ```
  2. 寫一支小腳本（或用 telegram-mcp 的 `session_string_generator.py`）登入一次，輸入手機碼，產出 session string
  3. 復制輸出
- **填到哪**：GitHub repo Secrets → `TELEGRAM_SESSION_STRING`
- **要不要填**：⏸ **選填**（用 MTProto 讀私有頻道才需要；`t.me/s/` 無登入不需要）

> ⚠️ 安全：`api_id`+`api_hash`+`session_string` 三件組等於你 TG 帳號的完整登入憑證，建議用拋棄式帳號。

---

## C. Worker 部署（擴展，選填）

要部署 CF Worker `/sub` API（階段 2）才填。**不部署 Worker，純靠 CF Pages 靜態訂閱也能用**。

### C1. `ADMIN_TOKEN` — Worker admin import token

- **值長什樣**：你自己設的隨機字串（例如用 `python -c "import secrets;print(secrets.token_urlsafe(32))"` 產一個）
- **去哪拿**：你自己產
- **填到哪**：
  ```bash
  cd src/worker
  npx wrangler secret put ADMIN_TOKEN
  # 貼上你產的字串
  ```
- **要不要填**：⏸ **選填**（部署 Worker 才需要）

### C2. D1 database ID

- **去哪拿**：
  ```bash
  cd src/worker
  npx wrangler d1 create nodes-db
  # 輸出會含 database_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  ```
- **填到哪**：`src/worker/wrangler.toml` 的 `database_id = "..."`（替換 placeholder）
- **要不要填**：⏸ **選填**（部署 Worker 才需要）

### C3. KV namespace ID

- **去哪拿**：
  ```bash
  npx wrangler kv namespace create CACHE
  # 輸出含 id: xxxxxx
  ```
- **填到哪**：`src/worker/wrangler.toml` 的 KV `id = "..."`
- **要不要填**：⏸ **選填**（部署 Worker 才需要）

---

## D. Tavily API Key（擴展，選填）

Source discovery skill（階段 9）的 MCP search 工具才用。**不開 discovery 不需要**。

- **值長什樣**：`tvly-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- **去哪拿**：https://tavily.com → sign up → API keys（免費 tier 1000 calls/月）
- **填到哪**：`.claude/mcp.json` 的 tavily 條目 `"TAVILY_API_KEY":"tvly-..."`
- **要不要填**：⏸ **選填**

---

## E. 本地 binary（不是 secret，但要裝）

### E1. `clash-speedtest`（驗活引擎）

- **現狀**：verify 是 stub，標 `unverified`
- **裝了**：verify 才能真測連通性 + 延遲
- **去哪拿**：https://github.com/faceair/clash-speedtest/releases → 下載對應 OS binary → 放進 PATH
  - Windows：下 `clash-speedtest-windows-amd64.exe`，改名 `clash-speedtest.exe`，放進 `C:\Users\user\project\bin\` 或任何 PATH 目錄
  - 或 `go install github.com/faceair/clash-speedtest@latest`（要有 Go）
- **要不要裝**：✅ **建議**——沒裝就只是「抓了不驗」的訂閱，裝了才是「驗過活的」訂閱

---

## F. 最終確認表（你照這檢查）

### 必填 3 個（最小可行）
- [ ] `CF_API_TOKEN` → GitHub repo Secrets
- [ ] `CF_ACCOUNT_ID` → GitHub repo Secrets
- [ ] `CF_PROJECT_NAME` → GitHub repo Secrets（先在 CF Pages 建好同名專案）

### 選填 — Telegram（階段 5 才用）
- [ ] `TELEGRAM_API_ID` → GitHub repo Secrets
- [ ] `TELEGRAM_API_HASH` → GitHub repo Secrets
- [ ] `TELEGRAM_SESSION_STRING` → GitHub repo Secrets

### 選填 — Worker（部署 `/sub` API 才用）
- [ ] `ADMIN_TOKEN` → `wrangler secret put`
- [ ] D1 database_id → `wrangler.toml`
- [ ] KV namespace id → `wrangler.toml`

### 選填 — Discovery
- [ ] `TAVILY_API_KEY` → `.claude/mcp.json`

### 本地 binary
- [ ] `clash-speedtest` binary 裝進 PATH

---

## G. 操作順序建議

**最快看到東西跑起來**：
1. 填必填 3 個（CF token + account id + project name）
2. CF Pages 建專案 `proxy-aggregator`，build output `output`
3. `git init` + commit + push 到 GitHub
4. GitHub Actions `*/30` cron 開始跑，每 30 min 更新 output/ + 部署 Pages
5. 訂閱 URL：`https://proxy-aggregator.pages.dev/clash.yaml` 等

**要驗活**：裝 clash-speedtest binary → verify 從 stub 變真測

**要 TG 源**：填 TG 三件組 → 階段 5 開工

**要 Worker API**：填 C1-C3 → `wrangler deploy` → 訂閱 URL 變 `https://<worker>.dev/sub`

---

## H. `.env` 本地檔（選填，本地開發用）

若你要本地跑 telegram-mcp 或 Worker dev，建 `.env`（已 gitignore）：

```env
# 從 my.telegram.org 拿
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_SESSION_STRING=

# 從 dash.cloudflare.com 拿
CF_API_TOKEN=
CF_ACCOUNT_ID=

# 自己產（python -c "import secrets;print(secrets.token_urlsafe(32))")
SUBCONVERTER_ADMIN_TOKEN=

# GitHub PAT（若 Worker 要 push 回 repo）
GITHUB_PAT=
```

**絕對不要把 .env commit**——.gitignore 已經擋了。
