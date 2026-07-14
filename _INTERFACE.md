# 共享介面契約 — 所有 subagent 必須遵守

> 根目錄 `$ROOT` = `C:\Users\win10\Documents\Free-Proxy`
> 平台：Windows，Python 3.12，Node 22。

## CLI 介面（Stage 1 定義，Stage 3/6 引用）

```bash
python src/aggregator/cli.py fetch    # 抓 sources.json 全部 enabled 源 → state/staging.jsonl
python src/aggregator/cli.py parse   # 解析 staging.jsonl → dedup → SQLite nodes 表
python src/aggregator/cli.py verify  # 跑 clash-speedtest → 回填 alive/latency_ms → state/live.jsonl
python src/aggregator/cli.py emit    # live.jsonl → output/{clash.yaml,singbox.json,v2ray-base64.txt}
python src/aggregator/cli.py all     # fetch + parse + verify + emit（CI 用）
```

## 檔案路徑（絕對固定）

| 檔案 | 用途 | 誰寫 |
|---|---|---|
| `state/sources.json` | 上游源清單 | Stage 1 |
| `state/staging.jsonl` | 原始節點（dedup by URI） | Stage 1 fetch |
| `state/live.jsonl` | 驗活後節點 | Stage 1 verify |
| `state/last-run.json` | {stage, ts, counts} | Stage 1 |
| `nodes.db` | SQLite（schema見 PRD 附錄） | Stage 1 |
| `output/clash.yaml` | clash 格式訂閱 | Stage 1 emit |
| `output/singbox.json` | sing-box 格式 | Stage 1 emit |
| `output/v2ray-base64.txt` | v2ray base64 | Stage 1 emit |
| `src/aggregator/*.py` | fetcher/parser/models/dedupe/cli | Stage 1 |
| `src/worker/sub-aggregator.ts` | CF Worker | Stage 2 |
| `src/worker/wrangler.toml` | Worker config | Stage 2 |
| `infra/docker-compose.yml` | subconverter sidecar | Stage 2 |
| `infra/d1/schema.sql` | D1 schema | Stage 1（本地共用） |
| `.claude/skills/*/SKILL.md` | crawl/check-nodes/publish/discover-sources | Stage 3 |
| `.claude/agents/*.md` | source-crawler/node-verifier | Stage 3 |
| `.claude/hooks/*.sh` | inject/deny/after-write/stop-check | Stage 3 |
| `.claude/mcp.json` | MCP servers | Stage 3 |
| `.claude/settings.json` | permissions + hooks | Stage 3 |
| `.claude/statusline.sh` | statusline | Stage 3 |
| `.github/workflows/fetch.yml` | */30 cron CI | Stage 6 |

## ProxyNode 模型（pydantic v2，所有 agent 對齊欄位）

```python
class ProxyNode(BaseModel):
    proto: str            # vmess|vless|trojan|ss|ssr|hysteria2|tuic
    host: str
    port: int
    uuid: str | None = None
    password: str | None = None
    method: str | None = None  # ss 加密方法
    sni: str | None = None
    net: str | None = None     # ws|tcp|grpc
    path: str | None = None
    host_header: str | None = None
    flow: str | None = None    # vless reality
    fp: str | None = None      # utls fingerprint
    alpn: str | None = None
    pbk: str | None = None     # reality public key
    sid: str | None = None     # reality short id
    raw: str                    # 原始 URI
    name: str | None = None
```

## dedup key
`hashlib.sha256(f"{host}:{port}:{proto}:{uuid or password or ''}:{sni or ''}".encode()).hexdigest()`

## 環境變數（.env，gitignore）
```
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_SESSION_STRING=
GITHUB_PAT=
CF_API_TOKEN=
CF_ACCOUNT_ID=
CF_D1_DATABASE_ID=
SUBCONVERTER_ADMIN_TOKEN=
```
