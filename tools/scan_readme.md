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
# 預設 enabled=false，需先在 config/gray_sources.yaml 的 scan 段設 enabled: true
python src/aggregator/scanner.py
```

或帶參數覆蓋：

```bash
python src/aggregator/scanner.py --rate 5000 --shards tools/scan_shards.txt
```

scanner 內部依序執行：

1. **masscan wrapper**：`masscan -p<ports> --rate <rate> -iL shards -oG scan.gnmap`
   解析 gnmap 輸出取 open host:port。
2. **nmap -sV wrapper**：對 open host:port 跑
   `nmap -sS -sV -Pn --script banner,fingerprint-strings`，解析取 service + banner。
3. **協議辨識 + 節點重建**：從 port/banner 推測 ss / vmess / trojan /
   hysteria2；對配置不當（無 auth / 預設憑證）的服務用常見默認值重建 URI。
4. **輸出**：可用 URI 寫 `state/gray_nodes.jsonl`（與 G1 共用格式），
   leads 寫 `state/recon-leads.jsonl`，summary 寫 stdout + `state/last-run.json`。

### 3.3 等效手動指令（若要直接用 CLI）

```bash
# masscan（注意需 root 或 setcap cap_net_raw）
sudo masscan -p8388,443,8080,2052,2083,2087,2096,8443,7001 \
  --rate 10000 -iL tools/scan_shards.txt -oG state/scan.gnmap

# 從 gnmap 抽 open IP
awk '/Ports:/{print $2}' state/scan.gnmap | sed 's/^Host: //' > state/live_ips.txt

# nmap -sV 對 live IPs
nmap -sS -sV -Pn --script banner,ssl-cert,http-enum -iL state/live_ips.txt \
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

## 5. 預設憑證嘗試（lead 級，不 brute force）

只對**推測為配置不當**的服務嘗試，憑證表為少量常見默認值（非字典爆破）：

- **ss**：method `aes-256-gcm`，password `shadowsocks`、`123456`、`password`
  → 重建 `ss://YWVzLTI1Ni1nY206c2hhZG93c29ja3M=@host:port#name`
- **vmess**：WS+TLS，path `/` 或 `/vmess`，net `ws`，tls `tls`
  UUID 重用從其他免費源抓到的 UUID（scanner 接 `state/gray_nodes.jsonl`
  既有 vmess UUID 作 candidate）；若無 candidate 則用全零 UUID
  `00000000-0000-0000-0000-000000000000`（配置不當常見值）。
- **trojan**：password `trojan`、`123456`、`admin`
  → 重建 `trojan://trojan@host:443?...`

**有 auth 的服務只記 lead 不嘗試**（如 ssl-cert 顯示真實域名、
banner 顯示已配置 auth 的 vmess）。憑證猜測結果標 `credential_guess: true`，
不寫入 `gray_nodes.jsonl` 的「已驗證」節點；recovery 的 URI 標
`recovered: true` + `source: scanner`。

## 6. 輸出格式

### `state/gray_nodes.jsonl`（與 G1 共用）

每行一個 URI 字串（G3 讀這個倒進 resin）：

```jsonl
ss://YWVzLTI1Ni1nY206c2hhZG93c29ja3M=@1.2.3.4:8388#scan-ss
vmess://eyJ2IjoiMiIsInBzIjoi...
trojan://trojan@5.6.7.8:443?security=tls&type=tcp#scan-trojan
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
  "scanned_ips": 256,
  "open_ports": 12,
  "services_identified": 8,
  "nodes_recovered": 3,
  "leads": 8
}
```

## 7. 為何不在本環境實際掃描

- **法律 / ToS**：本機 Windows 環境無授權目標，掃公網即違反 ISP 與目標端 ToS。
- **工具缺失**：本機多半無 masscan/nmap，scanner 會 log skip（這正是驗收要求）。
- **環境限制**：sandbox 阻斷大量 outbound SYN，掃描結果不可信。
- **設計取捨**：scanner 的價值在 VPS 上離線產 leads 給人類審核，
  非 CI 內即時跑。預設 `enabled: false` 強化此取捨。

所以本交付只含程式碼 + 文件，不執行實際掃描。
