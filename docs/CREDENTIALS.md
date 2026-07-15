# 你要填的 Credentials — 完整清單

> 掃遍 config + cli + workflow + mcp 整理出來。分「必填」「選填」「已填」。
> 無 credential 的功能（self-owned CT recon、本地 gitleaks、TG web-preview、V2Board fingerprint）都能跑，不在此列。

---

## ✅ 已部署（值存 secrets / .env，不進 repo）

> 這些 credential 不寫死在 code（repo 已 public）。值存在 GitHub Secrets（CI）或本地 .env。

| Credential | 存哪 | 備註 |
|---|---|---|
| `RESIN_ADMIN_TOKEN` | .env / GitHub Secrets | resin admin（本地 Docker） |
| `RESIN_PROXY_TOKEN` | resin Docker env（本地） | 數據面 token |
| `RESIN_URL` | .env / 預設 `http://localhost:2260` | 本地 resin |
| `ADMIN_TOKEN`（Worker） | GitHub Secrets + Cloudflare Worker secret | `wrangler secret put ADMIN_TOKEN`；cli publish 必填 |
| `WORKER_URL` | 預設 `https://proxy-sub-aggregator.proxy-aggregator.workers.dev` | Worker URL（非 secret） |
| D1 database_id | `src/worker/wrangler.toml` | 資源 id（非 secret） |
| KV id | `src/worker/wrangler.toml` | 資源 id（非 secret） |

> ⚠️ 歷史 commit 曾寫死這些值，已輪換（舊值失效）。新值只在 secrets，勿再 commit。

---

## 🔴 必填（CI 要跑一定要，GitHub repo Settings → Secrets）

這 3 個不填，push 上去後 fetch.yml 的 publish 步驟會用 fallback（已寫死，能跑），但建議填進 secrets 覆蓋：

| Secret | 去哪拿 | 填到 |
|---|---|---|
| `CF_API_TOKEN` | dash.cloudflare.com/profile/api-tokens → Create Token（Edit Cloudflare Pages 模板） | GitHub repo Secrets |
| `CF_ACCOUNT_ID` | dash.cloudflare.com 首頁右下 Account ID（`96068336d8c04d47d2a4d6806026def8`） | GitHub repo Secrets |
| `CF_PROJECT_NAME` | 自己取（如 `proxy-aggregator`），先在 CF Pages 建同名專案，build output `output` | GitHub repo Secrets |

> 這 3 個填了，CI 才會自動部署 CF Pages。不填也能靠 Worker fallback 跑訂閱，但 Pages 分片 + RSS 不會更新。

---

## 🟡 選填 — 灰管道（每個 credential 解鎖一條管道）

### Shodan / FOFA / Quake（面板指紋掃）

| Env | 去哪拿 | 解鎖 | 免費額 |
|---|---|---|---|
| `SHODAN_API_KEY` | shodan.io → Register → API Keys | gray_sources Shodan 查詢 | 100 query/月 |
| `FOFA_EMAIL` + `FOFA_KEY` | fofa.info → 注册 → 個人中心 | gray_sources FOFA 查詢 | 1 次/月（很摳） |
| `QUAKE_KEY` | quake.360.net → 注册 → API Key | gray_sources Quake 查詢 | 免費有額度 |

**填法**：建 `.env` 檔（已 gitignore），或直接設系統環境變數。

### Telegram（MTProto 深歷史爬取）

web-preview（`t.me/s/`）不用 credential 已能跑。要爬深歷史 + 私有頻道才填：

| Env | 去哪拿 | 解鎖 |
|---|---|---|
| `TELEGRAM_API_ID` | my.telegram.org/apps → Create app（數字） | tg_recon MTProto + tg_recon MTProto |
| `TELEGRAM_API_HASH` | 同上（32 hex） | 同上 |
| `TELEGRAM_SESSION_STRING` | 本地跑 `telethon` 登入一次產出 | 同上 |

**填法**：`.env` 或 GitHub repo Secrets（CI 要用）。⚠️ 用拋棄式帳號，三件組等於 TG 完整登入憑證。

### GitHub（code search dorking）

本地 gitleaks 不用 credential。要 GitHub code search 才填：

| Env | 去哪拿 | 解鎖 |
|---|---|---|
| `GITHUB_TOKEN` | github.com/settings/tokens → fine-grained PAT（public repo read） | github_dork code search（10/min） |
| `GITHUB_PAT` | 同上（給 MCP github server 用） | `.claude/mcp.json` github MCP |

**填法**：`.env` 或系統環境變數。

### SecurityTrails（被動 DNS 歷史記錄）

crt.sh 不用 credential。要歷史 A record 才填：

| Env | 去哪拿 | 解鎖 | 免費額 |
|---|---|---|---|
| `SECURITYTRAILS_API_KEY` | securitytrails.com → Register → API | ct_recon passive DNS | 50 query/天 |

### Tavily（source discovery search）

discovery agent 才用，一般訂閱服務不需要：

| Env | 去哪拿 | 解鎖 | 免費額 |
|---|---|---|---|
| `TAVILY_API_KEY` | tavily.com → Sign up → API Keys | `.claude/mcp.json` tavily MCP + discover-sources skill | 1000 calls/月 |

### Panel 註冊密碼（gray_sources 自動註冊面板用）

| Env | 去哪拿 | 解鎖 |
|---|---|---|
| `PANEL_PASSWORD` | 自己設一個密碼 | gray_sources 面板自動註冊 |

**填法**：`.env`。⚠️ 用拋棄式 email（如 `gray@protonmail.com`）。

---

## ⚫ 灰/黑管道要你填目標（非 credential，是授權目標）

這些預設 disabled/空，要你自己填合法授權的目標才會跑：

| Config 檔 | 填什麼 | 解鎖 |
|---|---|---|
| `config/self_nodes.yaml` | 自有 VPS 的 host/port/uuid/protocol | publish-self 倒自有節點 |
| `config/v2board_targets.yaml` | 自有/授權 V2Board 面板 host:port | v2board-recon --exploit（CVE-2026-39912 chain） |
| `tools/scan_shards.txt` | 合法授權的掃描目標 CIDR | scanner 公網掃描（要先 `enabled: true`） |
| `config/github_dorks.yaml` 的 `self_org` | 你的 GitHub org 名 | trufflehog 自有 org 稽核 |
| `config/ct_watch.yaml` 的 `watch_domains` | 想監控的機場域名 | ct-recon 監控新 cert |

---

## 📋 .env 範本（本地用，已 gitignore）

建 `.env` 在專案根目錄：

```env
# === 灰管道（選填，有才跑）===
SHODAN_API_KEY=
FOFA_EMAIL=
FOFA_KEY=
QUAKE_KEY=
SECURITYTRAILS_API_KEY=
PANEL_PASSWORD=

# === Telegram（MTProto 深歷史）===
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_SESSION_STRING=

# === GitHub ===
GITHUB_TOKEN=
GITHUB_PAT=

# === Tavily（discovery，選填）===
TAVILY_API_KEY=
```

**GitHub repo Secrets**（CI 用，不用建 .env）：`CF_API_TOKEN`、`CF_ACCOUNT_ID`、`CF_PROJECT_NAME`、`ADMIN_TOKEN`、`WORKER_URL`、`TELEGRAM_API_ID`、`TELEGRAM_API_HASH`、`TELEGRAM_SESSION_STRING`。

---

## 優先級建議

1. **必填 3 個 CF secrets** → CI 開始自動跑
2. **`config/self_nodes.yaml`** 填你自有 VPS → 品質最穩的自有節點進池
3. **`GITHUB_TOKEN`** → 解鎖 GitHub dork（自有 org 稽核）
4. **`SHODAN_API_KEY`** → 解鎖面板指紋掃（免費 100/月夠用）
5. 其餘按需

不用 credential 的現在就能跑：`ct-recon`、`github-dork`（本地 gitleaks）、`tg-recon`（web-preview）、`v2board-recon`（fingerprint）、`publish-self`。
