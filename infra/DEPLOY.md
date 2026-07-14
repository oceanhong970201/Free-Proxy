# Deploy — proxy-sub-aggregator

> 兩個元件：subconverter（Docker sidecar）+ Cloudflare Worker（D1 + KV + cron）。
> 環境：Windows / Node 22。Worker 程式碼在 `src/worker/`。

## ✅ 實際部署狀態（2026-07-14 已完成）

| 資源 | 值 |
|---|---|
| CF 帳號 ID | `96068336d8c04d47d2a4d6806026def8` |
| workers.dev subdomain | `proxy-aggregator` |
| Worker URL | `https://proxy-sub-aggregator.proxy-aggregator.workers.dev` |
| D1 database | `nodes-db` (id `1b837756-1913-43e7-b727-2d5a23bb8a78`) — schema 已套用 |
| KV namespace | `proxy-sub-aggregator-CACHE` (id `a8cc252082fc4736b5e9ce897cd33f37`) |
| ADMIN_TOKEN secret | 已設（值存 `.admin_token.tmp`，gitignore） |
| Cron trigger | `0 */2 * * *`（每 2h） |
| Worker version | 最新 `8b5c4e66-...`（含 hash async fix） |

### 端點
- `GET /health` → `{ok:true, ts}`
- `GET /sub` → base64-joined v2ray 訂閱（KV 快取 60s）
- `POST /admin/import` → base64 節點清單，header `X-Admin-Token`，回 `{imported:N}`

### 訂閱 URL（直接可用）
```
https://proxy-sub-aggregator.proxy-aggregator.workers.dev/sub
```
v2ray base64 訂閱，含 vmess/vless/trojan/ss/hysteria2/hy2。

### 重新倒入節點
```bash
cd C:\Users\win10\Documents\Free-Proxy
python -c "
import httpx, base64
W='https://proxy-sub-aggregator.proxy-aggregator.workers.dev'
ADMIN=open('.admin_token.tmp').read().strip()
raw=open('output/v2ray-base64.txt',encoding='utf-8').read().strip()
payload=base64.b64encode(base64.b64decode(raw)).decode()  # already base64
# 上面是 no-op; 直接用 raw text:
nodes=base64.b64decode(raw).decode().splitlines()
payload=base64.b64encode(('\n'.join(nodes)).encode()).decode()
r=httpx.post(W+'/admin/import', headers={'X-Admin-Token':ADMIN}, content=payload, timeout=120)
print(r.status_code, r.text)
"
# 清 KV 快取讓 /sub 即時反映新節點:
cd src/worker && npx wrangler kv key delete "sub-render" --namespace-id=a8cc252082fc4736b5e9ce897cd33f37
```

### 重新部署 Worker（改碼後）
```bash
cd src/worker
npx tsc --noEmit           # 型別檢查
npx wrangler deploy        # 部署
```

### 已知修復
- `handleImport` 的 `hash()` 是 async，原本 `stmt.bind(hash(uri))` 拿到 Promise 拋 Error 1101。改成 `await Promise.all(parsed.map(hash))` 預先算好。
- `parser.py` clash YAML / sing-box JSON 來源的 `raw` 原本存 `json.dumps(dict)`（clash JSON），改用 `node_to_uri()` 重建 `vmess://` / `vless://` URI。

---

## 0. 前置（首次部署才需要，已完成可跳過）

```powershell
cd C:\Users\win10\Documents\Free-Proxy\src\worker
npm install        # 安裝 wrangler / typescript / @cloudflare/workers-types
npx wrangler login  # 瀏覽器登入 Cloudflare（首次）
```

## 1. subconverter Docker sidecar

### 1.1 啟動
```powershell
cd C:\Users\win10\Documents\Free-Proxy
docker compose -f infra\docker-compose.yml up -d
```

### 1.2 驗證
```powershell
curl http://localhost:25500/version
# 預期回傳 subconverter 版本字串
```

### 1.3 訂閱轉換測試
subconverter 接受 base64 編碼的訂閱 URL 作為 `url` 參數：

```powershell
# 假設 Worker 已部署且 /sub 回傳 base64 節點清單
$raw = (Invoke-WebRequest "https://<worker>.workers.dev/sub").Content
$targetUrl = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("https://<worker>.workers.dev/sub"))
# 透過 subconverter 轉成 clash YAML
curl "http://localhost:25500/sub?target=clash&url=$targetUrl"
```

### 1.4 停止
```powershell
docker compose -f infra\docker-compose.yml down
```

> 注意：勿用公開 subconverter backend（會洩訂閱 URL 給第三方）。自架 Docker sidecar。

## 2. Cloudflare Worker 部署

### 2.1 建立 D1 資料庫
```powershell
npx wrangler d1 create nodes-db
# 把回傳的 database_id 填進 src\worker\wrangler.toml 的 [[d1_databases]] database_id
```

### 2.2 建立 KV namespace
```powershell
npx wrangler kv namespace create CACHE
# 把回傳的 id 填進 src\worker\wrangler.toml 的 [[kv_namespaces]] id
```

### 2.3 套用 schema
```powershell
cd C:\Users\win10\Documents\Free-Proxy
npx wrangler d1 execute nodes-db --file=infra\d1\schema.sql --remote
```
（本地離線測試可加 `--local`）

### 2.4 設定 admin token secret
```powershell
cd src\worker
npx wrangler secret put ADMIN_TOKEN
# 於提示輸入一個強隨機字串，記住它（之後 POST /admin/import 帶 X-Admin-Token）
```
> 勿用 vars（會寫進 toml 並曝光）；用 secret。

### 2.5 部署
```powershell
npx wrangler deploy
```
部署後記下 `https://proxy-sub-aggregator.<subdomain>.workers.dev`。

## 3. 驗證

```powershell
# health
curl https://<worker>.workers.dev/health
# {"ok":true,"ts":...}

# import（base64 過長建議用檔案 body）
$nodes = "vmess://...`nvless://..."   # 換行分隔的 URI 清單
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($nodes))
curl -X POST https://<worker>.workers.dev/admin/import `
  -H "X-Admin-Token: <你的 token>" `
  -H "Content-Type: text/plain" `
  -d $b64
# {"imported":N}

# /sub（base64 附件下載）
curl -O -J https://<worker>.workers.dev/sub
```

### 預期行為
- `POST /admin/import` 錯 token → 401。
- `GET /sub` 連打第二次，D1 query 計數不增（KV 60s 快取命中）。
- `crons = ["0 */2 * * *"]` 每 2 小時觸發 `scheduled` handler（stub log）。

## 4. 本地 `wrangler dev` 測試

```powershell
cd src\worker
npx wrangler d1 create nodes-db --local   # 第一次：建立本地 D1
npx wrangler d1 execute nodes-db --file=..\..\infra\d1\schema.sql --local
npx wrangler kv namespace create CACHE --local
$env:ADMIN_TOKEN = "dev-test-token"
npx wrangler dev --local
```

開另一個視窗測試：
```powershell
curl http://localhost:8787/health
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("vmess://demo`nvless://demo2"))
curl -X POST http://localhost:8787/admin/import -H "X-Admin-Token: dev-test-token" -H "Content-Type: text/plain" -d $b64
curl http://localhost:8787/sub
```

## 5. 型別檢查

```powershell
cd src\worker
npm install
npx tsc --noEmit
```
預期：零錯誤（依賴 `@cloudflare/workers-types` 提供的 `D1Database` / `KVNamespace` / `ExecutionContext` 型別）。
