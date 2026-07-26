# 共享介面契約 — 所有 subagent 必須遵守

> 根目錄 `$ROOT` = `C:\Users\win10\Documents\Free-Proxy`
> 平台：Windows，Python 3.12，Node 22。
>
> **維護註記（2026-07-26）**：節點身份與去重以 `src/aggregator/models.py`（`ProxyNode` +
> `ProxyNode.dedup_key`）與 `src/aggregator/dedupe.py` 為**唯一真實來源**；下方欄位表僅供對照，
> 與碼衝突時以碼為準。檔案路徑表保留少數早期項目（`after-write.sh` / `stop-check.sh` /
> `.claude/mcp.json` 已於後續重構移除），僅供歷史參考。

## CLI 介面（Stage 1 定義，Stage 3/6 引用）

```bash
python src/aggregator/cli.py fetch    # 抓 sources.json 全部 enabled 源 → state/staging.jsonl
python src/aggregator/cli.py parse   # 解析 staging.jsonl → dedup → SQLite nodes 表
python src/aggregator/cli.py verify  # 兩層 clash-speedtest → 回填 alive/latency_ms/download_speed → state/live.jsonl
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

## ProxyNode 模型（pydantic v2，`extra="forbid"`，所有 agent 對齊欄位）

> 完整定義見 `src/aggregator/models.py`。以下依用途分組（節錄要點欄位）。

```python
class ProxyNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # 連線核心
    proto: str            # vmess|vless|trojan|ss|ssr|hysteria2|tuic|juicity
    host: str
    port: int
    uuid: str | None = None
    alter_id: int | None = None    # VMess alterId
    password: str | None = None
    method: str | None = None      # ss/ssr cipher 或 vmess security
    # 傳輸 / TLS
    sni: str | None = None
    net: str | None = None         # tcp|ws|grpc|http|h2|xhttp|httpupgrade
    transport_mode: str | None = None  # XHTTP mode
    path: str | None = None
    host_header: str | None = None
    flow: str | None = None
    packet_encoding: str | None = None
    fp: str | None = None
    alpn: str | None = None
    pbk: str | None = None         # reality public key
    sid: str | None = None         # reality short id
    spider_x: str | None = None
    security: str | None = None    # none|tls|reality
    tls: bool | None = None
    utls: bool | None = None
    skip_cert_verify: bool | None = None
    # SSR / Hysteria2 obfs
    protocol: str | None = None
    protocol_param: str | None = None
    obfs: str | None = None
    obfs_param: str | None = None
    # TUIC / Juicity
    congestion_control: str | None = None
    udp_relay_mode: str | None = None
    # 序列化與顯示
    raw: str                        # 原始 URI（不進語意鍵）
    name: str | None = None
    # 執行期 liveness / 來源（不進語意鍵）
    source: str | None = None
    alive: bool | None = None
    latency_ms: int | None = None
    download_speed: float | None = None
    content_hash: str | None = None
```

支援協定：`vmess|vless|trojan|ss|ssr|hysteria2|tuic|juicity`（`hysteria`/`hy2` 正規化為 `hysteria2`）。
支援傳輸：`tcp|ws|grpc|http|h2|xhttp|httpupgrade`。

## dedup key（語意連線鍵，`SEMANTIC_KEY_VERSION = proxy-node-semantic-v1`）

節點身份 = **整條連線設定**，不是 `host:port`。同一 `host:port` 但憑證／傳輸不同即為**不同節點**。

`ProxyNode.dedup_key()` = 對 `model_dump` 取 `sha256`，**排除**下列非連線欄位：
`raw`、`name`、`source`、`alive`、`latency_ms`、`download_speed`、`content_hash`。
大小寫不敏感欄位正規化：`proto`、`host` 轉小寫；`sni`、`net`、`security` 轉小寫；憑證與 path 保持逐位元組。

```python
# src/aggregator/models.py::ProxyNode.dedup_key
excluded = {"raw", "name", "source", "alive", "latency_ms", "download_speed", "content_hash"}
values = self.model_dump(exclude=excluded, exclude_none=False)
values["proto"] = (self.proto or "").lower()
values["host"] = (self.host or "").lower()
for key in ("sni", "net", "security"):
    if isinstance(values.get(key), str):
        values[key] = values[key].lower()
sha256(json.dumps(values, sort_keys=True, separators=(",", ":")))
```

`dedupe.dedupe_nodes` 另加一道 **exact、大小寫敏感的 raw-URI guard**（憑證／path／fragment 可能大小寫敏感；空 `raw` 不互撞）。

> ⚠️ 舊版鍵 `sha256("{host}:{port}:{proto}:{cred}:{sni}")` **已淘汰**，勿再使用。

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
