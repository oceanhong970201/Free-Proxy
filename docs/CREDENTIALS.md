# Credentials 與環境設定

> 最後更新：2026-07-16
> 本清單描述程式會讀取的設定，不宣稱任何 secret 或遠端資源目前已配置。請勿把實際值寫進文件、程式、workflow 或 commit。

## 1. 最小需求

### 只產生本機輸出

`fetch`、`parse`、`emit` 本身沒有必填 API credential。完整核心流程仍需要：

- 可存取已啟用來源的網路；
- `clash-speedtest` binary（`verify` 必要，並非 secret）；
- Python 相依套件。

缺少驗證 binary 時 `verify` 會失敗，不會把節點標成未驗證後繼續發布。

### 發布到 Worker

| 名稱 | 類型 | 放置位置 | 用途 |
|---|---|---|---|
| `ADMIN_TOKEN` | secret、必填 | Worker secret；本機 `.env` 或 GitHub Actions secret | 驗證 `POST /admin/import` 的 `X-Admin-Token` |
| `WORKER_URL` | 非 secret、必填 | 本機 `.env` 或 workflow environment | Worker base URL，不含 `/admin/import` |

同一個 `ADMIN_TOKEN` 值必須同時存在於 Worker secret 與 publisher 執行環境；程式沒有 hardcoded token 或匿名發布路徑。

設定 Worker secret：

```powershell
Set-Location src\worker
npx.cmd wrangler secret put ADMIN_TOKEN
```

### 部署 Cloudflare Pages（若啟用）

| 名稱 | 類型 | 用途 |
|---|---|---|
| `CF_API_TOKEN` | secret | Pages deploy；權限應限制到目標帳戶與 Pages 編輯 |
| `CF_ACCOUNT_ID` | identifier | Cloudflare account identifier |
| `CF_PROJECT_NAME` | 非 secret | Pages project 名稱 |

Pages 與 Worker 是兩條不同發布路徑。缺少 Pages 設定不應改用內建值冒充成功；相關 deployment step 應被明確停用或失敗。Worker publish 仍必須另外提供 `WORKER_URL` 與 `ADMIN_TOKEN`。

## 2. Worker 資源設定（非 secret）

下列值保存在 `src/worker/wrangler.toml`：

- D1 `database_id`；
- KV namespace `id`；
- Worker name、compatibility date 與 cron。

資源 ID 雖不是 credential，也可能暴露環境結構；只應提交預期公開的環境設定。檔案中有 ID 不代表遠端資源存在或 schema 已完成 migration。

可選 Worker 變數：

| 名稱 | 用途 |
|---|---|
| `HEALTH_MAX_AGE_SECONDS` | `/health` 可接受的 snapshot 最大年齡 |

## 3. 可選功能的 credentials

這些設定不屬於核心 `all` 流程。缺少時，對應獨立命令應跳過該資料源或明確回報未設定，而不是影響核心 fetch/verify/publish。

| 名稱 | 使用模組 | 備註 |
|---|---|---|
| `GITHUB_TOKEN` | `github-dork` | GitHub code search；若本機 `gh` 已登入，模組可使用 CLI auth |
| `SECURITYTRAILS_API_KEY` | `ct-recon` | 可選 passive DNS 查詢；crt.sh 路徑不需要 key |
| `SHODAN_API_KEY` | `gray_sources` | 可選 intelligence API |
| `FOFA_EMAIL`, `FOFA_KEY` | `gray_sources` | 必須成對設定 |
| `QUAKE_KEY` | `gray_sources` | 可選 intelligence API |
| `PANEL_PASSWORD` | `gray_sources` | 只在 config 明確啟用且列出 approved targets 時使用 |
| `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION_STRING` | `tg-recon` | MTProto 保留欄位；目前實作只支援無登入 web-preview，因此無需填寫。未來啟用時三者皆應視同完整登入憑證 |
| `RESIN_ADMIN_TOKEN` | `publish-resin`, `publish-self` | 獨立 Resin 發布命令 |
| `RESIN_URL` | Resin publisher | 非 secret；未設定時依程式預設值 |

與目標相關的 allowlist／設定檔不是 credentials，但仍需明確配置：

- `config/self_nodes.yaml`
- `config/gray_sources.yaml` 的 `enabled` gate 與 `approved_targets`
- `config/v2board_targets.yaml`
- `config/ct_watch.yaml`
- `config/github_dorks.yaml` 的 `self_org`

預設的空清單或 `enabled: false` 不代表功能已執行。

## 4. 非 secret 環境變數

| 名稱 | 用途 |
|---|---|
| `PUBLIC_BASE_URL` | `output/feed.xml` 的公開 channel link |
| `WORKER_URL` | Worker base URL |
| `WORKER_BASE_URL` | GitHub repository variable；health workflow 的 Worker base URL，未設定時檢查失敗 |

`ALLOW_FIXTURE_FALLBACK=1` 僅供本機測試刻意啟用測試資料。正式環境與 CI 發布流程不應設定它；正常 fetch 必須在任何已啟用來源失敗時保留前一份 staging 並回傳失敗。

## 5. 本機 `.env`

Aggregator import 時會讀取專案根目錄 `.env`，`override=False`，所以 PowerShell、服務或 CI 已提供的環境變數具有優先權。`.env` 已在 `.gitignore` 中；仍應在 commit 前檢查 staged diff。

範例（只填實際需要的項目）：

```dotenv
# Core Worker publish
WORKER_URL=https://YOUR_WORKER.workers.dev
ADMIN_TOKEN=

# Static RSS link
PUBLIC_BASE_URL=https://YOUR_PUBLIC_BASE

# Optional recon/discovery modules
GITHUB_TOKEN=
SECURITYTRAILS_API_KEY=
SHODAN_API_KEY=
FOFA_EMAIL=
FOFA_KEY=
QUAKE_KEY=
PANEL_PASSWORD=

# Reserved for a future Telegram MTProto implementation; leave blank today
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_SESSION_STRING=

# Optional local Resin
RESIN_URL=http://127.0.0.1:2260
RESIN_ADMIN_TOKEN=
```

Cloudflare deploy credentials 通常應放在 GitHub Actions secrets 或本機 Wrangler 登入狀態，而不是專案 `.env`。

## 6. GitHub Actions 設定建議

- Secret：`ADMIN_TOKEN`、`CF_API_TOKEN`，以及任何可選 API key/session。
- Repository variable：`WORKER_BASE_URL`（health workflow 必填）。Variable 或 environment value 另包括 `WORKER_URL`、`CF_ACCOUNT_ID`、`CF_PROJECT_NAME`、`PUBLIC_BASE_URL`；若 workflow 目前從 `secrets.*` 取非敏感值，也必須依 workflow 實際 context 設定。
- 使用 environments 時，對 production deploy 加 required reviewers。
- `GITHUB_TOKEN` 優先使用 Actions 自帶的短期 token；不要因自動 commit 而建立廣權限 PAT。
- Cloudflare token 使用最小帳戶／資源範圍並定期輪替。

## 7. 安全檢查

```powershell
# 只列名稱，不輸出 secret 值
gh secret list

Set-Location src\worker
npx.cmd wrangler secret list
```

另外確認：

1. `git status --short` 沒有 `.env`、session、token 暫存檔；
2. log 與 exception 不輸出完整 header 或 payload credentials；
3. Worker import 使用 HTTPS 且回應契約完全匹配；
4. secret 疑似外洩時先輪替，再處理歷史；
5. 遠端資源與 secret 是否存在必須實際查詢，不能從文件中的舊狀態推定。
