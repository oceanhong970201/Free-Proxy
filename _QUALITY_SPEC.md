# 高質量節點管線 — 共享規格（本次 subagent 任務對齊）

> 目標：個人用、高質量節點。verify 不再只測延遲，要測下載速度。
> 三個 agent 並行，各碰不同檔案，無衝突。

## 質已知的部署值（寫死，不要 placeholder）

- Worker URL: `https://proxy-sub-aggregator.proxy-aggregator.workers.dev`
- ADMIN_TOKEN: 存 GitHub Secrets + Cloudflare Worker secret（`wrangler secret put ADMIN_TOKEN`）；已輪換，舊值失效
- D1 database_id: `1b837756-1913-43e7-b727-2d5a23bb8a78`
- KV id: `a8cc252082fc4736b5e9ce897cd33f37`
- clash-speedtest binary: `C:\Users\user\project\go\bin\clash-speedtest.exe`（CI 用 ubuntu，要 `go install`）

## 質量篩選策略（兩段式）

**Tier 1 — 延遲篩選（fast mode，全部節點）**
- `clash-speedtest -c clash.yaml --fast -concurrent 50`
- 保留 latency < 1000ms 的（alive）
- 這層快，3677 節點約 4h（CI matrix 拆 5 job 並行 → ~50min）

**Tier 2 — 速度測試（download mode，只測 Tier 1 存活的）**
- `clash-speedtest -c clash_alive.yaml -concurrent 10`（無 --fast，跑下載測速）
- `-download-size 10485760`（10MB，預設 50MB 太慢）
- `-max-latency 1s -min-download-speed 5`（MB/s，低於 5MB/s 淘汰）
- 結果含 download speed，用來排名

**最終輸出**：按 download speed desc 排序的 alive 節點，取 top 100 進 Worker。

## 新增 CLI 指令

```bash
python src/aggregator/cli.py verify        # Tier1+Tier2，回填 D1 alive/latency_ms/download_speed
python src/aggregator/cli.py publish       # 讀 live.jsonl，只取 alive，按 download_speed desc 排序，top 100，base64 後 POST /admin/import，清 KV
python src/aggregator/cli.py all           # fetch→parse→verify→emit→publish
```

## ProxyNode 新欄位（加到 models.py）
- `download_speed: float | None = None`（MB/s）
- `alive: bool | None = None`（已是）

## DB schema 新欄位
`nodes` 表加 `download_speed REAL` 欄位（ALTER TABLE 或在 schema.sql 加）。

## Worker 不改
Worker `/sub` 查 `alive=1 ORDER BY latency_ms` 不動——publish 只倒 alive 的進去，所以 /sub 自然只回活的。但排序要改：Worker 應 `ORDER BY download_speed DESC`。**agent 3 順便改 Worker SQL**（src/worker/sub-aggregator.ts）。

## 檔案分工（嚴格不重疊）

| Agent | 檔案 | 任務 |
|---|---|---|
| 1 | `src/aggregator/models.py` + `src/aggregator/cli.py` + `infra/d1/schema.sql` | 加 download_speed 欄位、兩段式 verify、publish 指令、all 加 publish |
| 2 | `src/aggregator/emit.py` + `output/_headers` + `output/feed.xml` | emit 只含 alive、按 download_speed desc 排序、產 RSS feed、_headers 設 no-cache |
| 3 | `.github/workflows/fetch.yml` + `src/worker/sub-aggregator.ts` | matrix chunking（5 job 並行驗活）、emit 後 curl POST /admin/import、Worker SQL 改 ORDER BY download_speed DESC |

## 質量設定檔
建 `config/quality.yaml`：
```yaml
max_latency_ms: 1000
min_download_speed_mbps: 5
top_n_publish: 100
tier1_concurrent: 50
tier2_concurrent: 10
download_size_bytes: 10485760  # 10MB
```
agent 1 讀這個檔決定參數。
