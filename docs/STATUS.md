# Project Status & Maintenance Guide

> 最後更新：2026-07-16
> 本文件描述目前儲存庫中的程式與維護契約，不代表任何遠端 Worker、D1、KV、Pages 或訂閱端點已完成部署。遠端狀態必須依本文的驗證指令另外確認。

## 1. 目前基線

本專案把多個已啟用的訂閱來源轉成統一節點模型，經完整代理設定驗證後，產生 Clash/Mihomo、sing-box、V2Ray base64 與 RSS 輸出；通過品質門檻的節點可再以單一 snapshot 發布到 Worker。

核心流程：

```text
state/sources.json
  -> fetch（完整來源 snapshot）
  -> state/staging.jsonl
  -> parse + validate + semantic dedupe
  -> nodes.db + state/live.jsonl
  -> verify（TCP pre-filter、延遲、下載速度）
  -> emit（四個靜態產物）
  -> publish --strict（Worker JSON snapshot）
  -> D1 + KV -> /sub、/sub?format=clash、/health
```

`python src/aggregator/cli.py all` 只執行核心 `fetch -> parse -> verify -> emit -> publish --strict`。灰管道、recon、自有節點與 Resin 發布均為明確的獨立命令，不會隱含在核心流程內。

## 2. Fail-closed 契約

### Fetch

- 只處理 `state/sources.json` 中 `enabled: true` 的來源。
- 每個來源依序嘗試主 URL 與 `mirrors[]`；404/410 也會繼續嘗試鏡像。
- 一輪中只要有任一已啟用來源失敗、回空內容或未產生有效 staging 記錄，命令即以失敗結束，並保留上一份 `state/staging.jsonl`。
- 新 staging 先完整寫入暫存檔，再以 replace 取代舊 snapshot。
- 測試資料只可在本機測試明確設定 `ALLOW_FIXTURE_FALLBACK=1` 時使用；正式環境不應設定此變數。

### Parse

- staging 每行必須是物件，且 `source_id`、`raw` 型別正確。
- 只接受目前設定中已知且啟用的 `source_id`。
- 節點在 parse 邊界驗證必要的 host、port 與協議憑證；不完整節點不會進入正常輸出。
- SQLite 保存完整 `ProxyNode` JSON；同一 host/port 但不同憑證的節點仍是獨立設定。

### Verify

- 驗證身分以完整 URI／代理設定為準，不以 `host:port` 共用驗證結果。
- TCP pre-filter 只用來排除不可連線端點；Tier 1 測延遲，Tier 2 測下載速度。
- 品質門檻由 `config/quality.yaml` 管理；目前預設延遲上限為 1000 ms、下載速度下限為 5 MB/s。
- 每個代理在獨立 verifier process 中執行並以受限 concurrency 平行處理，避免單一 core 卡死拖住整批。個別 process 逾時或非零只會把該 URI 記為失敗；若整個 wave 都失敗、輸出名稱／欄位不符或沒有可辨識資料，整輪仍 fail closed 並保留舊 snapshot。
- 缺少驗證程式或 `--max-runtime` 到期時命令回傳非零；正常暫停會保存進度供下一輪續跑，不會把未驗證節點當成存活。
- resume fingerprint 綁定完整代理輸出、品質設定與 v4 進度 schema；輸入、門檻或 verifier contract 改變時會重開驗證。

### Emit 與 Publish

- 正常 `emit` 只選 `alive is True` 的節點；不會把 `alive is None` 當成可發布。
- 空集合、損壞的 live 記錄或非預期格式轉換失敗時，命令失敗並保留上一份輸出 snapshot。對目標 client 明確不支援的協議，只能走有測試且會在 summary 列出原因／數量的顯式 skip；未知 transport 不可靜默降級。
- `publish --strict` 另外要求節點達到設定的下載速度下限，再依速度、延遲排序並套用 `top_n_publish`。
- strict 結果為空時不會降級成非 strict 發布；Worker 上一份 snapshot 會保留。
- 不加 `--strict` 的手動模式仍只會選 `alive is True`，但不套用下載速度下限。正式管線使用 strict 模式。

## 3. Worker snapshot 合約

Python publisher 對 `POST /admin/import` 傳送 `Content-Type: application/json`，並帶 `X-Admin-Token`：

```json
{
  "version": 1,
  "snapshot_id": "TIMESTAMP-UNIQUE_ID",
  "expected_count": 1,
  "nodes": [
    {
      "uri": "PROXY_URI",
      "alive": true,
      "latency_ms": 120,
      "download_speed": 8.5,
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

Worker 會驗證：

- `version`、`snapshot_id`、`expected_count` 與 `nodes.length` 一致；
- URI 不重複且每筆欄位型別、範圍合法；`model.raw` 必須等於外層 `uri`；
- JSON publisher 的完整 `model` 會成為 D1 `node_json` 的 authoritative 內容，並同步可查詢 scalar 欄位；
- 節點 upsert、舊 snapshot 停用與 `import_state` 更新在同一個 D1 batch 交易中完成；
- 寫入後的 active count、current snapshot count 與 `import_state` 完全相符；
- KV cache 清除完成。

成功回應至少須同時符合：

```json
{
  "ok": true,
  "complete": true,
  "snapshot_id": "TIMESTAMP-UNIQUE_ID",
  "imported": 1,
  "expected": 1,
  "model_persisted": true
}
```

Publisher 會逐項比對回應；HTTP 2xx 但欄位不符仍視為失敗。

## 4. Worker 讀取端點

| 端點 | 行為 |
|---|---|
| `GET /sub` | 目前 active snapshot 的 V2Ray base64 訂閱 |
| `GET /sub?format=clash` | 目前 active snapshot 的 Clash YAML |
| `GET /health` | 檢查 D1、KV、snapshot 完整性與新鮮度；失敗時回 503 且 `ok:false` |
| `POST /admin/import` | 受 `X-Admin-Token` 保護的 version 1 JSON snapshot import |

`/health` 的判定不只看 HTTP 連通性。健康檢查必須解析 JSON 並確認 `ok === true`、snapshot counts 一致且未超過 `HEALTH_MAX_AGE_SECONDS`（未設定時使用 Worker 內建預設）。

## 5. D1 schema 與部署狀態

- Fresh D1：只套用 `infra/d1/schema.sql`。
- 既有 D1：依序且各只執行一次 `infra/d1/migrations/0002_atomic_snapshots.sql`、`infra/d1/migrations/0003_full_node_model.sql`；兩者都成功並查驗後，才部署新版 Worker。
- `0002` 新增 `nodes.snapshot_id`、品質／snapshot indexes 與 `import_state`；`0003` 補齊完整連線模型欄位（包含 `alter_id`、transport/security/SSR/TUIC 欄位與 authoritative `node_json`）。兩者都包含非冪等的 `ALTER TABLE`，不得重複執行。
- 儲存庫內的 `wrangler.toml`、資源 ID 或 URL 只代表設定值，不證明遠端資源仍存在、schema 已套用或目前版本已部署。

完整順序與驗證方式見 [`infra/DEPLOY.md`](../infra/DEPLOY.md)。

## 6. 靜態輸出

正常 emit 會以暫存檔加 replace 更新以下四個檔案：

| 檔案 | 格式 |
|---|---|
| `output/clash.yaml` | Clash/Mihomo YAML |
| `output/singbox.json` | sing-box JSON |
| `output/v2ray-base64.txt` | 換行 URI 的 UTF-8 base64 |
| `output/feed.xml` | RSS 2.0 |

RSS 的公開連結基底由 `PUBLIC_BASE_URL` 控制。輸出使用方式與離線檢查見 [`output/README.md`](../output/README.md)。

## 7. 本機維護命令

```powershell
# Python 相依
python -m pip install -r requirements.txt

# 核心分段執行
python src/aggregator/cli.py fetch
python src/aggregator/cli.py parse
python src/aggregator/cli.py verify
python src/aggregator/cli.py emit
python src/aggregator/cli.py publish --strict

# 或一次執行核心流程
python src/aggregator/cli.py all
```

`verify` 需要 `clash-speedtest` 位於 `PATH`、`$GOPATH/bin`，或由
`CLASH_SPEEDTEST_BIN` 指向其完整路徑。`publish` 需要 `WORKER_URL` 與
`ADMIN_TOKEN`。根目錄 `.env` 會自動載入，但既有系統／CI 環境變數優先。

## 8. 驗證清單

```powershell
# Python
$env:PYTHONPATH = "src"
python -W error -m pytest -q
python -m compileall -q src

# Worker
Set-Location src\worker
npm.cmd ci
npm.cmd run typecheck
npm.cmd test
```

部署後另外確認：

1. `/health` 回 HTTP 200 且 JSON `ok:true`；
2. `snapshot.expected === snapshot.imported === nodes.alive === nodes.current_snapshot`；
3. `/sub` 可 base64 decode；
4. `/sub?format=clash` 可由目標客戶端解析；
5. 最近一次 `publish --strict` 的 `snapshot_id` 與 Worker 回應一致。

## 9. 維護注意事項

- GitHub Actions 的 schedule 是 best-effort，cron 表達式不保證準點執行。
- 不要手動編輯 `output/` 產物；應修正 parser/emitter 後重跑完整驗證。
- 不要在未完成 verify 時發布，亦不要因新 snapshot 為空而覆蓋舊 snapshot。
- protocol 與 transport 的支援度以 parser/emitter 測試為準；不得把未知 transport 靜默降級成 TCP。
- 遠端 migration 與 Worker deploy 是獨立的營運動作；程式測試通過不等於遠端已更新。
