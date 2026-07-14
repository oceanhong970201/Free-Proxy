# 免費 Proxy 節點挖掘項目 — 當前知識基線

> 記錄時間：2026-07-14
> 狀態：基線知識，待 workflow 補充最新管道與工具鏈

---

## 一、GitHub 倉庫（主礦脈）

### 搜尋關鍵字
`v2ray free nodes`、`clash free nodes`、`shadowsocks subscribe`、`vmess subscribe`、`vless subscribe`、`trojan subscribe`、`free proxy subscribe`、`nodecollect`、`nodes-pool`、`clash-meta nodes`、`hysteria2 nodes`、`tuic nodes`、`shadowrocket nodes`、`机场订阅`、`免费订阅`、`节点池`、`proxypool`、`free airport`、`v2rayN nodes`、`sing-box nodes`、`mihomo nodes`

### GitHub topic 頁
- https://github.com/topics/v2ray
- https://github.com/topics/clash
- https://github.com/topics/shadowsocks
- https://github.com/topics/proxy
- https://github.com/topics/free-proxy
- https://github.com/topics/vmess

### 訂閱鏈接加速格式
```
https://raw.githubusercontent.com/<user>/<repo>/<branch>/<file>
https://raw.gitmirror.com/<user>/<repo>/<branch>/<file>
https://cdn.jsdelivr.net/gh/<user>/<repo>@<branch>/<file>
https://fastly.jsdelivr.net/gh/<user>/<repo>@<branch>/<file>
https://ghproxy.com/https://raw.githubusercontent.com/...
https://mirror.ghproxy.com/https://raw.githubusercontent.com/...
```

---

## 二、GitHub Actions 自跑（核心玩法）

上游數據來源：
1. 其他 GitHub 倉庫的 raw 文件
2. 機場免費試用訂閱
3. Telegram 頻道訊息
4. 論壇貼文（NodeLoc、HostLoc、V2EX、LinuxDo、1024、Nodeseek）
5. 免費機場聚合站
6. FreeVPN 網站
7. Shodan / FOFA / Censys 搜索（灰）
8. 公網掃描（灰）
9. Clash 訂閱轉換 API

### 爬蟲核心邏輯
- 拉取上游訂閱（base64 解碼）
- 解析 vmess/vless/trojan/ss/ssr/hysteria2/tuic/clash YAML
- 去重 key = `host:port:protocol`
- 驗活：mihomo 子進程 / asyncio 過代理測 generate_204
- 輸出多格式 + Actions 定時 push（每 3~6 小時）

### Actions cron
```yaml
on:
  schedule:
    - cron: '0 */3 * * *'
  workflow_dispatch:
```

---

## 三、Telegram 頻道與 Bot

- TG 內搜 `v2ray`、`free vpn`、`clash`、`ssr`、`节点`、`机场`
- `https://t.me/s/<channel>` 網頁版爬
- Telethon / MTProto API 自動抓訊息，正則提取 proxy 鏈接

```python
from telethon import TelegramClient
async for msg in client.iter_messages(channel, limit=2000):
    extract_proxy_links(msg.text)
```

---

## 四、免費機場試用訂閱

- Google 搜 `机场 免费 试用`、`机场 白嫖`
- v2rayfree.eu.org、ss 域名站、機場導航站
- 訂閱特徵：`https://xxx.com/link/abcdefg?clash=1`，動態換節點

---

## 五、訂閱聚合站 / subconverter

- subconverter（tindy2013/subconverter）— 訂閱轉換神器
- 公共後端：`https://sub.xxx.com/sub?target=clash&url=<base64上游>`
- 自架後端最穩

---

## 六、論壇與社區

- HostLoc（hostloc.com）
- NodeLoc（nodeseek.com）
- V2EX（v2ex.com）/go/proxy /go/vps
- LinuxDo（linux.do）
- 1024 / 91 網絡板塊
- Reddit r/Piracy、r/freevpns
- LowEndTalk（lowendtalk.com）

### 爬蟲策略
- Discourse 論壇 API：`/posts.json`、`/t/<topic_id>.json`
- HostLoc Discuz HTML 抓
- 定時抓新帖訂閱鏈接

---

## 七、Shodan / FOFA / Censys 灰區掃描

### Shodan 語法
```
"HTTP/1.1 200 OK" "vmess"
product:"V2Ray"
port:8080,8443,2052 "vmess"
"V2Ray/v"
country:"CN" port:443 network:"Cloudflare"
```

### FOFA 語法
```
banner="V2Ray"
header="V2Ray"
protocol=="http" && header="V2Ray"
```

### 灰管道
- 開放註冊的免費面板（v2board / xboard）
- 默認密碼 ss 服務
- CF Workers 反代節點特徵掃描

---

## 八、公網端口掃描（深灰）

masscan + zmap + nmap -sV
- ss: 8388, 8389, 8080
- vmess ws: 80, 8080, 2052, 2083, 2087, 2096, 8082, 8083
- vmess tls: 443, 8443, 2053
- trojan: 443
- hysteria2: 443 (udp)

瓶頸：多數要鑑權，能直接用的少。

---

## 九、Cloudflare Workers / Pages 自建

- CF Workers 部署 vless+ws+tls，零成本
- 免費額度 10 萬請求/天
- 項目：搜 `cloudflare workers vless`、`edgetunnel`

---

## 十、機場導航站

- v2rayfree.eu.org
- xn--ssstv61l.xyz
- clashnode.com
- freeproxy.cc
- free-ss.site

---

## 十一、訂閱鏈接格式總結

```
vmess://eyJ...
vless://uuid@host:port?security=tls&type=ws&path=/...&sni=...#name
trojan://password@host:443?...
ss://method:pass@host:port
ssr://base64
https://raw.githubusercontent.com/.../clash.yaml
https://xxx.com/link/xxx?clash=1
https://sub.xxx.com/sub?target=clash&url=...
```

---

## 十二、項目架構

```
[上游源池] → [抓取層 asyncio+httpx] → [解析層] → [去重層] → [驗活層 mihomo] → [轉換層 subconverter] → [輸出層] → [分發層 jsdelivr/gitmirror]
```

---

## 十三、必讀上游項目

- proxypool / ProxyPool / proxypoolSS
- ssrsub
- v2ray-node
- free-ss
- clash-speedtest
- subconverter
- mihomo（clash-meta）
- sub-web
- edgetunnel
- nodeflux / NodeFlux
- airport-traffic

---

## 待補充（workflow 進行中）

- [ ] 最新 2025-2026 GitHub 倉庫與 Actions
- [ ] 最新 TG 頻道與 bot
- [ ] 最新論壇與社區動態
- [ ] Shodan/FOFA 最新語法與工具
- [ ] 最新免費機場試用
- [ ] CF Workers/Pages 最新方案
- [ ] MCP servers（爬蟲/fetch/瀏覽器/搜索）
- [ ] Claude Code skills/hooks
- [ ] Python/Node 爬蟲套件
- [ ] 驗活/去重/轉換最新工具
