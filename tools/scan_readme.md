# 公網掃描 — leads 產出工具

> G2 公網掃描 agent 的操作手冊。對應程式碼：`src/aggregator/scanner.py`。
> 對應規格：`_GRAY_SPEC.md` 的 `scan` 段 + PRD 階段 10/A5。

## 0. 性質與限制

公網端口掃描與後續服務指紋識別在多數司法管轄區屬灰色行為：

- **ISP / 雲商 ToS**：DO、Vultr、Linode、AWS、GCP 等主流 VPS 供應商 ToS
  明文禁止未經同意的 internet scanning。在被掃目標端也可能觸發 abuse 投訴。
- **法律風險**：部分地區將「未經授權對他人系統進行端口探測 / 服務指紋
  取得 / 憑證猜測」視為未授權存取，即使未實際登入。
- **授權前提**：**只在你擁有或已取得書面授權的網段上執行**。掃描目標
  清單 `tools/scan_shards.txt` 預設為空，正是此原因。

本工具**只產 leads**（host:port + 推測協議 + 可能的預設憑證），**不主動
連線驗證**配置不當的服務、不對有 auth 的服務做 brute force、不對洩漏
憑證的服務完成 login。Resin pool 的健康探測由 resin 內部
`cloudflare.com/cdn-cgi/trace` 完成，不需這裡驗活。

## 1. 部署環境

**不要在本機跑，不要在 GitHub Actions 跑**（runner IP 會被 ban，
且違反 GHA ToS）。在專用 VPS 上跑：

- 選擇容許 research scanning 的供應商，或自建裸金屬。
- 防火牆隔離 research user，log 所有 outbound scan 供自身 audit。
- `--rate` bounded（預設 10000，可調降）。

## 2. 安裝依賴

```bash
# Debian/Ubuntu
apt install -y masscan nmap

# 或從 source
git clone https://github.com/robertdavidgraham/masscan
cd masscan && make && make install

# nmap scripts（banner, ssl-cert, http-enum 已隨 nmap-nses 套件）
```

確認在 PATH：

```bash
which masscan nmap
```

`scanner.py` 在任一工具不在 PATH 時會 log 並 skip 該階段，不會崩潰。

## 3. 操作流程

### 3.1 填入授權目標

編輯 `tools/scan_shards.txt`，每行一個 CIDR 或 IP（`#` 開頭為註解）：

```
1.2.3.0/24
8.8.8.8
```

檔案為空（無非註解行）時，`scanner.py` log `no scan targets` 並返回。

### 3.2 執行 scanner

```bash
# 預設 enabled=false；CLI 會保留這個 gate
python src/aggregator/cli.py scan-targets --shards tools/scan_shards.txt
```

或帶參數覆蓋：

```bash
python src/aggregator/cli.py scan-targets --force --rate 5000 --shards tools/scan_shards.txt
```

scanner 內部依序執行：

1. **discovery wrapper**：優先使用
   `masscan -p<ports> --rate <rate> -iL shards -oG scan.gnmap`；masscan 不在
   PATH 時使用 bounded `nmap -sT -Pn -n --open` fallback。解析輸出取 open host:port。
2. **nmap -sV wrapper**：對 open host:port 跑
   `nmap -sT -sV -Pn -n --script banner,ssl-cert,http-enum,fingerprint-strings`，
   並只對 discovery 已發現的 host/port 做指紋識別。
3. **協議辨識 + 節點重建**：從 port/banner 推測 ss / vmess / trojan /
   hysteria2；若明確開啟候選重建，使用少量預設值產生候選 URI。
4. **輸出**：leads 寫 `state/recon-leads.jsonl`；候選寫入
   `state/gray_nodes.jsonl` 的 disabled/quarantine JSON record，summary 寫 stdout
   + `state/last-run.json`。候選不等於已通過代理握手。

### 3.3 等效手動指令（若要直接用 CLI）

```bash
# masscan（注意需 root 或 setcap cap_net_raw）
sudo masscan -p8388,443,8080,2052,2083,2087,2096,8443,7001 \
  --rate 10000 -iL tools/scan_shards.txt -oG state/scan.gnmap

# 從 gnmap 抽 open IP
awk '/Ports:/{print $2}' state/scan.gnmap | sed 's/^Host: //' > state/live_ips.txt

# nmap -sV 對 live IPs（只在同一份明確 allowlist 內）
nmap -sT -sV -Pn -n --script banner,ssl-cert,http-enum -iL state/live_ips.txt \
  -oX state/scan.xml
```

## 4. 協議辨識規則

| 協議 | TCP/UDP | 端口 | 辨識特徵 |
|---|---|---|---|
| ss | TCP | 8388,8389,8080,443 | **靜默**（無 banner）；8388 open 即記 ss lead |
| ssr | TCP | 8388,80,443 | 同樣靜默 |
| vmess | TCP | 8080,2052,2082,2086,2095,443,2053,2083,2087,2096,8443 | nginx WS+TLS 特徵：`400 Bad Request` / `404 Not Found` / `nginx` banner，`/` 回 400 |
| vless+reality | TCP | 443,8443,2053 | TLS 後靜默；JARM 匹配 CDN 但 ASN 非 CDN |
| trojan | TCP | 443,8443,2053 | HTTPS（有 ssl-cert）；證書 CN 任意 |
| hysteria2 | UDP | 443,8443,4443,36712 | QUIC/HTTP3，ALPN h3；nmap 對 UDP 弱 |

## 5. 候選憑證重建（未驗證）

只有在 `scan.leads_only: false` 時，才會對指紋顯示配置不當的服務重建少量
候選 URI。這是資料整理，不會宣稱登入或代理握手成功：

- **ss**：method `aes-256-gcm`，password `shadowsocks`、`123456`、`password`
  → 重建 `ss://YWVzLTI1Ni1nY206c2hhZG93c29ja3M=@host:port#name`
- **vmess**：WS+TLS，path `/` 或 `/vmess`，net `ws`，tls `tls`
  UUID 重用從其他免費源抓到的 UUID（scanner 接 `state/gray_nodes.jsonl`
  既有 vmess UUID 作 candidate）；若無 candidate 則用全零 UUID
  `00000000-0000-0000-0000-000000000000`（配置不當常見值）。
- **trojan**：password `trojan`、`123456`、`admin`
  → 重建 `trojan://trojan@host:443?...`

有明顯 auth/真實網域特徵的服務只記 lead。候選 lead 標
`credential_guess: true`；寫入 `gray_nodes.jsonl` 時一律為
`enabled:false`、`review_status:"pending"`、`watermark_suspect:true`，需經既有
verify 與人工審核。

## 6. 輸出格式

### `state/gray_nodes.jsonl`（與 G1 共用）

每行一個 quarantine JSON 物件（G3 只接受明確 enable 且完成審核的記錄）：

```jsonl
{"raw":"ss://YWVzLTI1Ni1nY206c2hhZG93c29ja3M=@1.2.3.4:8388#scan-ss","uri":"ss://...","tier":"gray","source_channel":"scanner","enabled":false,"watermark_suspect":true,"review_status":"pending","credential_guess":true}
```

### `state/recon-leads.jsonl`

每行一個 JSON 物件：

```json
{"host":"1.2.3.4","port":8388,"proto_guess":"ss","banner":null,"source":"masscan","credential_guess":true,"recovered":false,"ts":1720900000}
{"host":"5.6.7.8","port":443,"proto_guess":"trojan","banner":"nginx","ssl_cn":"example.com","source":"nmap","credential_guess":false,"recovered":false,"ts":1720900000}
```

### summary

```
{
  "success": true,
  "scanned_ips": 256,
  "discovery_engine": "nmap",
  "open_ports": 12,
  "services_identified": 8,
  "nodes_recovered": 3,
  "leads": 8,
  "leads_only": true
}
```

## 7. 驗證方式

程式提供 deterministic fixture 測試與 nmap fallback。正式執行仍只使用
`tools/scan_shards.txt` 的明確目標；GitHub-hosted runner 不執行掃描。可先執行：

```bash
PYTHONPATH=src python -m pytest -q tests/test_g2_scanner.py tests/test_gray_sources.py
```
