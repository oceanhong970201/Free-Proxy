# 訂閱檔（CI 自動產物）

本目錄下的三個檔案由 GitHub Actions 權威管線（`.github/workflows/fetch.yml`）每 30 分鐘自動重新產生，**不要手動編輯**。

| 檔案 | 格式 | 用戶端 |
|---|---|---|
| `clash.yaml` | Clash / mihomo | Clash for Windows / Android, mihomo, FlClash |
| `singbox.json` | sing-box | sing-box, SFA, Koru |
| `v2ray-base64.txt` | v2ray base64 訂閱 | v2rayN / v2rayNG, Qv2ray |

## 更新頻率

- 排程：`*/30 * * * *`（每 30 分鐘整點 + 30 分一次）
- 管線：`fetch → parse → dedup → verify → emit → commit → CF Pages 部署 → jsDelivr purge`
- 逾時保護：每 job 上限 30 分鐘（遠低於 GitHub Actions 6 小時上限）
- 併發控制：`concurrency.group: aggregate`，新 run 不取消進行中的 run（`cancel-in-progress: false`），避免產物半寫。

## 訂閱 URL

假設倉庫為 `https://github.com/<owner>/<repo>`，預設分支 `main`。把下面的 `<owner>/<repo>` 換成實際值。

### 1. GitHub Raw（權威源，最即時，可能有 rate limit）

```
https://raw.githubusercontent.com/<owner>/<repo>/main/output/clash.yaml
https://raw.githubusercontent.com/<owner>/<repo>/main/output/singbox.json
https://raw.githubusercontent.com/<owner>/<repo>/main/output/v2ray-base64.txt
```

### 2. jsDelivr CDN（全球快取，CI commit 後主動 purge）

```
https://cdn.jsdelivr.net/gh/<owner>/<repo>@main/output/clash.yaml
https://cdn.jsdelivr.net/gh/<owner>/<repo>@main/output/singbox.json
https://cdn.jsdelivr.net/gh/<owner>/<repo>@main/output/v2ray-base64.txt
```

> 單檔 < 20 MiB（jsDelivr 上限）。CI 每次 commit 後對這三個檔執行 `curl -X PURGE`，確保快取立即反映新內容。

### 3. Cloudflare Pages（`*.pages.dev`，CF 邊緣快取）

```
https://<project>.pages.dev/clash.yaml
https://<project>.pages.dev/singbox.json
https://<project>.pages.dev/v2ray-base64.txt
```

> 專案名由 secret `CF_PROJECT_NAME` 指定。部署由 `.github/workflows/deploy-pages.yml`（在 `fetch-and-publish` 完成後觸發）或 `fetch.yml` 內建步驟執行。

## 健康檢查

`.github/workflows/health-check.yml` 每 6 小時打 Worker 的 `/health` 端點，失敗時自動開 issue（標籤 `health-check` / `ops`）。
