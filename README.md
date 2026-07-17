# Free-Proxy

以 Python 聚合、驗證並輸出多格式代理節點，並可把通過品質門檻的完整 snapshot 發布到 Cloudflare Worker（D1 + KV）。

> 儲存庫中的 URL、resource ID 與 tracked output 不代表遠端服務目前健康或已部署最新版。請以 workflow 結果、deployment ID 與 Worker `/health` JSON 為準。

## 核心可靠性

- **完整 fetch snapshot**：任一已啟用來源失敗時整輪失敗，保留前一份 staging。
- **完整代理身分**：不同憑證即使共用 host/port，也分別 parse、dedupe、verify。
- **驗證後輸出**：正常 emit 與 publish 只選 `alive is True`。
- **strict production publish**：另外要求下載速度達到 `config/quality.yaml` 門檻；空集合不降級發布。
- **atomic Worker import**：節點 upsert、舊 snapshot 停用與 `import_state` 在同一個 D1 batch 完成，並核對 snapshot counts。
- **fail-closed artifact update**：空資料或格式錯誤不覆蓋上一份輸出。

## 快速開始

```powershell
python -m pip install -r requirements.txt

# 需要 clash-speedtest 位於 PATH
python src\aggregator\cli.py fetch
python src\aggregator\cli.py parse
python src\aggregator\cli.py verify
python src\aggregator\cli.py emit
```

發布 Worker snapshot 前設定：

```powershell
$env:WORKER_URL = "https://YOUR_WORKER.workers.dev"
$env:ADMIN_TOKEN = "YOUR_ADMIN_TOKEN"
python src\aggregator\cli.py publish --strict
```

也可用 `python src\aggregator\cli.py all` 執行核心 `fetch -> parse -> verify -> emit -> publish --strict`。灰管道、recon、自有節點與 Resin 發布是獨立命令，不在 `all` 內。

## 輸出

| 檔案 | 格式 |
|---|---|
| `output/clash.yaml` | Clash/Mihomo YAML |
| `output/singbox.json` | sing-box JSON |
| `output/v2ray-base64.txt` | V2Ray base64 subscription |
| `output/feed.xml` | RSS 2.0 |
| `output/pipeline-status.json` | 去敏感化的遠端自動化狀態快照 |

不要直接編輯產物；修正 parser/emitter 後重新跑完整驗證與 emit。

## 測試

```powershell
$env:PYTHONPATH = "src"
python -m pip install -r requirements-dev.txt
python -W error -m pytest -q
python -m compileall -q src

Set-Location src\worker
npm.cmd ci
npm.cmd run typecheck
npm.cmd test
```

## D1 migration 摘要

- **Fresh D1**：只套用 `infra/d1/schema.sql`。
- **Existing D1**：部署新版 Worker 前，依序且各只執行一次：
  1. `infra/d1/migrations/0002_atomic_snapshots.sql`
  2. `infra/d1/migrations/0003_full_node_model.sql`

兩個 migration 都有非冪等 `ALTER TABLE`。先備份、查驗每一步，再 deploy Worker。完整命令見部署手冊。

## 文件

- [目前狀態與維護契約](docs/STATUS.md)
- [Credentials 與環境設定](docs/CREDENTIALS.md)
- [Worker / D1 / KV 部署](infra/DEPLOY.md)
- [本機營運 Dashboard](docs/DASHBOARD.md)
- [輸出格式、URL 範本與驗證](output/README.md)
- [需求與歷史設計背景](docs/PRD.md)

### 文件層級

上列 README、STATUS、CREDENTIALS、DEPLOY 與 output README 是現行操作依據。
根目錄底線開頭的研究檔、`docs/_gray_deep_research.md`、PRD 內的早期方案，
以及 `state/_*` 測試語料均屬歷史研究或 regression corpus；其中的版本、部署
範例與「目前」敘述不代表現行設定，也不應直接當成 production runbook。
