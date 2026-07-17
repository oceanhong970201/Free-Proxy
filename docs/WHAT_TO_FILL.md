# 設定填寫檢查表

> Canonical 說明以 [`CREDENTIALS.md`](CREDENTIALS.md) 為準。本頁只保留最短操作清單，避免複製 credential 值或過時部署狀態。

## 本機產生已驗證輸出

- [ ] `python -m pip install -r requirements.txt`
- [ ] 安裝 `clash-speedtest` 並確認可從 `PATH` 執行
- [ ] 檢查 `state/sources.json`：只啟用本輪必須成功的來源
- [ ] 執行 `fetch -> parse -> verify -> emit`

核心本機產物不需要 Cloudflare、Telegram 或 intelligence API credentials。缺少 `clash-speedtest` 時 verify 會失敗；未驗證節點不會作為正常輸出發布。

## 發布到 Worker

- [ ] `WORKER_URL`：publisher 使用的 Worker base URL
- [ ] `ADMIN_TOKEN`：同一值同時設定為 Worker secret 與 publisher secret/env
- [ ] D1 database ID 與 KV namespace ID 已填入 `src/worker/wrangler.toml`
- [ ] Fresh D1 只套用 `infra/d1/schema.sql`
- [ ] Existing D1 在 deploy 前依序、各一次套用 `0002_atomic_snapshots.sql` 與 `0003_full_node_model.sql`
- [ ] Worker typecheck/tests 通過後 deploy
- [ ] 執行 `python src/aggregator/cli.py publish --strict`
- [ ] `/health` 回 HTTP 200、JSON `ok:true` 且 snapshot counts 一致

Worker import 使用 version 1 JSON snapshot，不是 base64 body。沒有通過 strict 門檻的節點時，publisher 保留既有 Worker snapshot。

## 發布靜態 Pages（若啟用）

- [ ] `CF_API_TOKEN`
- [ ] `CF_ACCOUNT_ID`
- [ ] `CF_PROJECT_NAME`
- [ ] deployment workflow 成功，且實際 URL 回傳本次 output commit

這三項只供 Pages deployment；不會取代 Worker 的 `WORKER_URL`／`ADMIN_TOKEN`。

## 可選模組

只在需要對應獨立命令時填寫：

- [ ] GitHub search：`GITHUB_TOKEN`（或本機 `gh` auth）
- [ ] Passive DNS：`SECURITYTRAILS_API_KEY`
- [ ] Intelligence APIs：`SHODAN_API_KEY`、`FOFA_EMAIL` + `FOFA_KEY`、`QUAKE_KEY`
- [ ] Explicit approved-target panel flow：`PANEL_PASSWORD`，並在 config 開 gate/allowlist
- [ ] Telegram：目前只使用無登入 web-preview；MTProto 尚未實作，保留的 `TELEGRAM_API_ID`、`TELEGRAM_API_HASH`、`TELEGRAM_SESSION_STRING` 先留空
- [ ] Local Resin：`RESIN_URL`、`RESIN_ADMIN_TOKEN`

空白設定、空 allowlist 或 `enabled: false` 不代表功能已執行。

## `.env` 與 secret hygiene

根目錄 `.env` 會由 aggregator 自動載入，既有 shell／CI environment 優先。`.env`、session 與 token 暫存檔不得 commit。

```powershell
git status --short
git diff --cached --check
gh secret list
```

實際值、已部署狀態與 credential 輪替只能從對應平台查證，不應從舊文件推定。
