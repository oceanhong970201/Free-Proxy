# 灰色/黑色管道 + Resin 整合 — 共享規格

> 目標：用 Shodan/FOFA/Quake 面板指紋 + 公網端口掃描 + 繞 auth 找高質量節點，倒進本地 resin 節點池。
> Resin 是已部署的 sticky proxy pool（Docker，localhost:2260）。

## Resin 部署值（已驗證）

- URL: `http://localhost:2260`
- API base: `http://localhost:2260/api/v1`
- Admin auth: `Authorization: Bearer 48941200c6727066d94e2f77a2143e4a`（env `RESIN_ADMIN_TOKEN`）
- Proxy token: `c4bf84ee16922c1a78c359364bbfa43a12964eb6`（env `RESIN_PROXY_TOKEN`，數據面用）

## Resin API（已驗證可用）

### POST 訂閱（local content 直接倒節點）
```
POST /api/v1/subscriptions
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json
Body: {"name":"<sub-name>","source_type":"local","content":"vmess://...\nvless://...","enabled":true}
→ 201 Created, return {id, name, node_count}
```

### Refresh（解析 content 進節點池）
```
POST /api/v1/subscriptions/{id}/actions/refresh
Authorization: Bearer <ADMIN_TOKEN>
→ 200, 阻塞到完成，return {node_count, healthy_node_count}
```

### 列訂閱
```
GET /api/v1/subscriptions
```

### 刪訂閱
```
DELETE /api/v1/subscriptions/{id}
```

### 節點也會自動探測
resin 內部用 `https://cloudflare.com/cdn-cgi/trace` 探節點健康，不需我們驗活。

## 檔案分工（3 個 subagent，無衝突）

| Agent | 檔案 | 任務 |
|---|---|---|
| G1 灰管道爬蟲 | `src/aggregator/gray_sources.py`（新）+ `config/gray_sources.yaml`（新）| Shodan/FOFA/Quake API 查面板指紋（V2Board/Xboard/開放面板），抓開放註冊面板的試用訂閱 URL |
| G2 公網掃描 + auth 繞過 | `src/aggregator/scanner.py`（新）+ `tools/scan_shards.txt`（新）| masscan/zmap 掃公網端口（ss/vmess/trojan），nmap -sV 識別 banner，嘗試默認憑證/開放面板註冊拿訂閱 |
| G3 resin publisher | `src/aggregator/resin_publisher.py`（新）+ 改 `cli.py` 加 `publish-resin` 指令 | 把所有管道抓到的節點統一 POST 進 resin local subscription + refresh |

## 通用節點收集格式

三個 agent 都把抓到的節點（URI 字串）寫進 `state/gray_nodes.jsonl`（每行一個 URI），G3 讀這個檔倒進 resin。

```jsonl
vmess://eyJ...
vless://uuid@host:port?...
trojan://pwd@host:port?...
ss://...
```

## 灰色管道參數（config/gray_sources.yaml）

```yaml
# Shodan/FOFA/Quake API keys（從 env 讀，不要寫死）
shodan_api_key: ${SHODAN_API_KEY}
fofa_email: ${FOFA_EMAIL}
fofa_key: ${FOFA_KEY}
quake_key: ${QUAKE_KEY}

# 指紋查詢
shodan_queries:
  - 'http.html:"V2Board"'
  - 'http.title:"V2Board"'
  - 'http.html:"/api/v1/guest/comm/config"'
  - 'ssl.cert.subject.CN:"*.workers.dev" port:443,2053,2083,2087,2096,8443'
fofa_queries:
  - 'app="V2Board"'
  - 'app="Xboard"'
  - 'body="/api/v1/guest/comm/config"'
  - 'cert="www.microsoft.com" && port="443" && asn!="13335"'
quake_queries:
  - 'app:"V2Board"'
  - 'app:"Xboard"'
  - 'app:"sing-box"'

# 開放註冊面板嘗試
panel_register:
  default_email: gray@protonmail.com
  default_password: ${PANEL_PASSWORD}
  # V2Board/Xboard 註冊端點
  register_path: /api/v1/passport/auth/register
  # 註冊後拿訂閱 URL
  sub_path: /api/v1/user/getSubscribe

# 公網掃描
scan:
  # 在專用 VPS 跑，不在本地
  enabled: false
  ports_tcp: [8388, 443, 8080, 2052, 2083, 2087, 2096, 8443, 7001]
  ports_udp: [443, 36712, 51820]
  rate: 10000
  # 只產 leads，不主動連線測試洩漏憑證的服務
```

## 注意
- Shodan/FOFA/Quake API key 從環境變數讀，沒有就 skip 該管道
- 公網掃描預設 `enabled: false`，要 VPS + 人工開啟
- 繞 auth 只針對配置不當的開放服務（默認密碼、開放註冊面板），不對有 auth 的服務 brute force
- 所有結果寫 `state/gray_nodes.jsonl`，G3 統一倒 resin
