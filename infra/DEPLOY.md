# Worker / D1 / KV 部署手冊

> 最後更新：2026-07-16
> 儲存庫中的 URL、binding 與 resource ID 是設定資料，不是遠端部署完成證明。本手冊不宣稱目前遠端版本、schema、secret 或健康狀態；每次部署都必須執行最後的驗證步驟。

## 1. 元件與必要順序

核心服務包含：

1. Cloudflare Worker：`src/worker/sub-aggregator.ts`
2. D1：節點與目前 snapshot 狀態
3. KV：`/sub` render cache
4. `ADMIN_TOKEN` Worker secret

本機 `subconverter` sidecar 是可選工具，不是 Python typed emitters 或 Worker 的執行相依。

部署 atomic snapshot Worker 前，D1 必須先具備新 schema：

```text
確認目標帳戶／D1／KV
  -> 備份 D1
  -> fresh DB：套 schema.sql
     或
     existing DB：依序且各只執行一次 0002、0003 migrations
  -> 設定 ADMIN_TOKEN
  -> typecheck + tests
  -> deploy Worker
  -> strict publish 一份 snapshot
  -> 驗證 /health、/sub 與 snapshot counts
```

**不可先部署新 Worker 再補 migration。** 新 Worker 會讀寫 `nodes.snapshot_id` 與 `import_state`；舊 D1 尚未 migration 時 import 與 health 會失敗。

## 2. 前置檢查

以下命令以 PowerShell、專案根目錄為起點：

```powershell
Set-Location C:\path\to\Free-Proxy\src\worker
npm.cmd ci
npx.cmd wrangler whoami
npm.cmd run typecheck
npm.cmd test
```

確認 `src/worker/wrangler.toml` 的 D1 與 KV binding 指向本次要部署的環境。若使用多環境，請顯式指定對應 Wrangler environment，不要依賴目前 shell 的偶然狀態。

## 3. D1：fresh database

本節只適用於全新、尚未套過任何 schema 的 D1。

```powershell
Set-Location C:\path\to\Free-Proxy\src\worker

# 建立資源，將輸出的 ID 填入 wrangler.toml
npx.cmd wrangler d1 create nodes-db
npx.cmd wrangler kv namespace create CACHE

# Fresh DB 只套完整 schema；不要再跑 0002/0003 migrations
npx.cmd wrangler d1 execute nodes-db --remote --file=..\..\infra\d1\schema.sql

# 驗證關鍵物件
npx.cmd wrangler d1 execute nodes-db --remote --command="PRAGMA table_info(nodes);"
npx.cmd wrangler d1 execute nodes-db --remote --command="SELECT name FROM sqlite_master WHERE type='table' AND name='import_state';"
```

預期 `nodes` 具有 `node_json`、`download_speed`、`snapshot_id`，且存在 `import_state` 表。

## 4. D1：existing database migrations

本節只適用於既有 D1。先確認選到正確帳戶與 database，再備份：

```powershell
Set-Location C:\path\to\Free-Proxy\src\worker
$backup = Join-Path $env:TEMP ("nodes-db-before-atomic-migrations-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".sql")
npx.cmd wrangler d1 export nodes-db --remote --output=$backup
Write-Host "D1 backup: $backup"
```

在部署新 Worker **之前**，嚴格依序執行兩個 migration；只有前一個成功並完成查驗後才執行下一個：

```powershell
npx.cmd wrangler d1 execute nodes-db --remote --file=..\..\infra\d1\migrations\0002_atomic_snapshots.sql
npx.cmd wrangler d1 execute nodes-db --remote --file=..\..\infra\d1\migrations\0003_full_node_model.sql
```

`0002_atomic_snapshots.sql` 必須一次性執行，內容包括：

- `ALTER TABLE nodes ADD COLUMN snapshot_id TEXT`
- snapshot／quality indexes
- `import_state` 表

`0003_full_node_model.sql` 接著補齊既有 DB 的完整節點欄位，包括 `method`、`security`、TLS/transport/Reality、`alter_id`、SSR、TUIC/Juicity 相關欄位與 authoritative `node_json`。

兩個 migration 都不可重複執行；第二次執行會因欄位已存在而失敗。請在 deployment log 或 migration ledger 分別記錄 0002、0003 已完成。不要把「欄位已存在」錯誤一律忽略，因為同一檔案的後續 statement 可能未套用；應分別查驗：

```powershell
npx.cmd wrangler d1 execute nodes-db --remote --command="PRAGMA table_info(nodes);"
npx.cmd wrangler d1 execute nodes-db --remote --command="SELECT name FROM sqlite_master WHERE type IN ('table','index') AND (name='import_state' OR name LIKE 'idx_nodes_%') ORDER BY name;"
```

至少確認 `nodes` 具有 `snapshot_id`、`alter_id`、`protocol`、`obfs`、`congestion_control` 與 `node_json`，並確認 `import_state` 及預期 indexes 均存在。

Fresh DB 不執行本節的 0002/0003；fresh DB 使用上一節的完整 `schema.sql`。

## 5. Worker secret 與 deploy

為 `ADMIN_TOKEN` 產生強隨機值，並把同一值放入 publisher 執行環境。不要寫進 `wrangler.toml`：

```powershell
Set-Location C:\path\to\Free-Proxy\src\worker
npx.cmd wrangler secret put ADMIN_TOKEN
```

D1 schema，或 existing DB 的 0002、0003 migrations，全數驗證成功後才部署：

```powershell
# package.json 的 predeploy 會再次執行 typecheck 與 tests
npm.cmd run deploy
```

保留 deploy 輸出的 deployment/version ID 與 git commit SHA。遠端 deploy 是需要登入與網路的獨立動作；本機測試成功不代表此命令已執行。

## 6. Canonical import：Python strict publisher

推薦由 aggregator 建立 version 1 JSON snapshot，並嚴格核對 Worker 回應：

```powershell
Set-Location C:\path\to\Free-Proxy
$env:WORKER_URL = "https://YOUR_WORKER.workers.dev"
$env:ADMIN_TOKEN = "YOUR_ADMIN_TOKEN"
python src\aggregator\cli.py publish --strict
```

`publish --strict` 只會選 `alive is True` 且達到 `config/quality.yaml` 下載速度下限的節點。沒有合格節點時命令失敗並保留遠端舊 snapshot，不會改用未驗證或較低門檻資料。

Canonical request：

```http
POST /admin/import
Content-Type: application/json
X-Admin-Token: SECRET
```

```json
{
  "version": 1,
  "snapshot_id": "TIMESTAMP-UNIQUE_ID",
  "expected_count": 1,
  "nodes": [
    {
      "uri": "PROXY_URI",
      "alive": true,
      "latency_ms": 100,
      "download_speed": 12.5,
      "model": {
        "proto": "vless",
        "host": "edge.example",
        "port": 443,
        "uuid": "00000000-0000-0000-0000-000000000001",
        "raw": "PROXY_URI"
      }
    }
  ]
}
```

`model` 是完整 ProxyNode 物件（範例只列主要欄位），且 `model.raw` 必須與外層 `uri` 完全相同。Worker 會把完整 JSON 寫入 D1 `node_json`，並同步 schema 中的 scalar 欄位。成功回應必須同時包含 `ok:true`、`complete:true`、`model_persisted:true`、相同的 `snapshot_id`，且 `imported`、`expected` 均等於送出的 `expected_count`。只檢查 HTTP 2xx 不足以判定成功。

## 7. 部署後驗證

Fresh D1 在第一份完整 snapshot 匯入前，`/health` 回 503 是預期行為。完成 strict publish 後執行：

```powershell
$base = "https://YOUR_WORKER.workers.dev"
$health = Invoke-RestMethod "$base/health"
$health | ConvertTo-Json -Depth 8

if (-not $health.ok) { throw "Worker health ok=false" }
if ($health.snapshot.expected -ne $health.snapshot.imported) { throw "snapshot import count mismatch" }
if ($health.nodes.alive -ne $health.snapshot.expected) { throw "active node count mismatch" }
if ($health.nodes.current_snapshot -ne $health.snapshot.expected) { throw "current snapshot count mismatch" }

Invoke-WebRequest "$base/sub" -OutFile (Join-Path $env:TEMP "worker-sub.txt")
Invoke-WebRequest "$base/sub?format=clash" -OutFile (Join-Path $env:TEMP "worker-clash.yaml")
```

健康條件包含：

- D1 query 成功；
- KV probe 成功；
- `import_state` 完整；
- active rows 全部屬於目前 `snapshot_id`；
- snapshot 未超過 `HEALTH_MAX_AGE_SECONDS`。

健康檢查應同時要求 HTTP 200 與 JSON `ok:true`。HTTP body 可讀但 `ok:false`、counts 不一致或 snapshot 過舊都屬於失敗。

## 8. 本機 Worker 開發

本機 D1 與遠端 D1 分開初始化：

```powershell
Set-Location C:\path\to\Free-Proxy\src\worker
npx.cmd wrangler d1 execute nodes-db --local --file=..\..\infra\d1\schema.sql
$env:ADMIN_TOKEN = "dev-only-token"
npm.cmd run dev
```

本機測試用資料庫使用完整 `schema.sql`；不要對 fresh local DB 另外執行 0002/0003 migrations。

## 9. 可選 subconverter sidecar

只有在需要額外手動轉換時才啟動：

```powershell
Set-Location C:\path\to\Free-Proxy
docker compose -f infra\docker-compose.yml up -d
curl http://127.0.0.1:25500/version
```

啟用前確認 compose 將 port 綁在 `127.0.0.1`，且 image 使用經審查的固定版本或 digest，而不是浮動 `latest`。不要把帶 token 的私人訂閱 URL 送到第三方 converter。

停止：

```powershell
docker compose -f infra\docker-compose.yml down
```

## 10. Rollback 與事故處理

- Worker：保留上一版 deployment ID；新版本健康檢查失敗時，使用 Cloudflare deployment rollback 功能回到已知版本。
- D1：0002/0003 是 additive migrations，沒有自動 down migration。保留部署前 export，先停止新 import，再依事故程序於獨立資料庫驗證 restore。
- Snapshot：失敗的 import 不應停用目前可用 snapshot；若 import 後 cache invalidation 失敗，先查 D1 `import_state` 與 counts，再決定是否重試 cache 清除。
- Secret：疑似洩漏時先更新 Worker secret 與 publisher secret，再重新發布；不要把 token 貼進 issue 或 log。

## 11. 發布紀錄

每次 production deployment 至少記錄：

- git commit SHA；
- Worker deployment/version ID；
- D1 database name/id 與 migration 狀態；
- typecheck/test 結果；
- strict publisher 的 `snapshot_id` 與 count；
- `/health` JSON 驗證時間與結果。

沒有這些證據時，文件只描述預期流程，不應標示遠端部署為完成。
