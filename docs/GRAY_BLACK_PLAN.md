# Gray / Black 管線 — 2026 有效性核實與實作計劃

> **產生日期**：2026-07-26
> **核實方法**：七向量平行 web-search sweep（WebSearch + tavily，交叉比對 2025–2026 一手來源：NVD、VulnCheck、廠商 repo/release、官方 API 文件、附日期文章）。
> **前提**：本專案為運營者自有的免費節點聚合器；gray/black 向量在碼中**預設 `enabled:false`**、輸出隔離、須人工審核。本文只做事實核實與落地規劃，安全模型不放寬。
> **權威層級**：本文與 `STATUS.md` / `DEPLOY.md` 並列為現行規劃；取代 `PRD.md` 階段 10/15–19 中已過時的 gray/black 假設。

---

## 0. 判決一覽

| 向量 | 模組 | 2026 狀態 | 建議 | 波次 |
|---|---|---|---|---|
| A5 Telegram web-preview 抓取 | `src/aggregator/tg_recon.py` | ✅ valid | **implement-now** | W1 |
| 協定/生態升級（AnyTLS / 汰 SSR / verify） | `parser.py` `emit.py` `cli.py` `models.py` | ✅ valid | **implement-now** | W1 |
| 新增 2026 活躍 clearnet seed repos | `state/candidates.jsonl`（canary） | ✅ valid | **implement-now** | W1 |
| A8 Certificate Transparency + passive DNS | `src/aggregator/ct_recon.py` | ✅ valid（被動、低險） | **implement-now** | W2 |
| A4 GitHub code-dork（config 檔） | `src/aggregator/github_dork.py` | ✅ valid（洩密度已降） | **implement-now**（config 抓取）/ 洩密只記錄 | W2 |
| 面板搜尋引擎 Shodan / FOFA / Quake | `src/aggregator/gray_sources.py` | ✅ valid（門檻分歧） | **recon-only**（FOFA 優先） | W3 |
| A2 V2Board/Xboard CVE-2026-39912 | `src/aggregator/v2board_recon.py` | ✅ valid（真 CVE） | **recon-only**（指紋 OK；利用鏈只對自有授權） | W3 |
| G2 公網端口掃描 + 指紋 | `src/aggregator/scanner.py` | ⚠️ degraded | **drop / 封存** | — |

**核心結論**：2026 免費節點生態非常活躍，但**產出重心已從「灰黑偵查」移回「clearnet 聚合 + 更嚴格 verify」**。最高 CP 的動作是 Telegram 抓取、補齊協定（AnyTLS）、把活躍 seed repos 走正常 canary 晉升 —— 這些都不需要碰真正的黑產風險。真正的黑向量（面板利用、公網掃描）產出低、風險高，維持 recon-only 或直接封存。

---

## 1. implement-now 向量（W1–W2）

### 1.1 A5 — Telegram web-preview 抓取（`tg_recon.py`）✅ 最高 CP

**2026 現況**：無登入 `GET https://t.me/s/<channel>` 仍回**伺服器端渲染 HTML**，免登入、免 API key、免 JS;`?before=<message_id>` 反向翻頁仍有效。現場實測（2026-07-26，`t.me/s/vpnfail_v2ray`）直接吐出 `vless://` / `trojan:// `/ `ss://` URI,無登入牆。維護中的同類工具 `Surfboardv2ray/TGParse` 用的是**一模一樣**的技術。

**與 repo 假設的差異**：
- 現行 `tg_recon.py` 用最小 `data-post` id 算下一頁 `before`;Telegram 頁面其實有原生 `data-before="<id>"` cursor（TGParse 直接 regex `data-before="(\d*)"`）—— **改用原生 cursor 更穩**（pinned/service message 不會誤翻頁）。
- MTProto 保留路徑點名 telethon **正確且仍維護**（v1.44.0，2026-06-15;已搬到 Codeberg）。**pyrogram 已死**（作者 2024 失蹤）→ 若哪天啟用改用 telethon 1.44.x 或 `Kurigram`,**絕不用 pyrogram**。
- Web preview 只曝露每頻道**最近 ~500–1000 則**訊息 —— `max_pages` 調參時要明講這個天花板。
- 貼文格式已偏向 `vless://`（含 Reality,騎在 vless 裡）;repo 的 `URI_RE` 已涵蓋。

**動作**：
- [ ] `_earliest_message_id` 改讀原生 `data-before` attribute,fallback 才用 min(data-post)。
- [ ] `config/tg_channels.yaml` 補 2026 活躍頻道(從 GitHub topics `vmess`/`vless`/`hysteria2` + forward-from graph 探,honeytrap triage 照舊)。
- [ ] 維持 `enabled:false` + `watermark_suspect` + `honeytrap_triage` + 人工審核 → `resin_publisher` 只發 `enabled==true && watermark_suspect==false`。
- [ ] mtproto 路徑保留 stub,不啟用(帳號秒 ban 風險)。

**風險**：web-preview 無帳號/ToS ban 風險(純抓取);部分頻道關預覽(空 HTML,優雅處理);t.me 可能被 GFW/DNS 阻(已 log+skip);honeypot/浮水印節點(隔離 + 審核已擋)。

---

### 1.2 協定 / 生態升級（`parser.py` `emit.py` `models.py` `cli.py`）✅

**2026 現況**：`VLESS+REALITY`(Vision flow)是抗審查主流;`Hysteria2` 主打速度但 QUIC/UDP base 已被 GFW 針對(2024-04 起解 QUIC 首包 SNI,USENIX Security 2025),越來越需 Salamander obfs;`TUIC v5` 稀少式微;`SS-2022` 續存;`Trojan`/`Shadowsocks` 數量最多但品質低;`VMess` 遺留式微;**`SSR` 實質已死**(sing-box v1.6.0 移除)。**新入場者 `AnyTLS`**(~2025-03,對付 TLS-in-TLS 指紋)—— sing-box + mihomo 一等公民,**Xray-core 不支援**。

**核心版本(pin/target)**：Xray-core `v1.260327.0`(2026-03-27)、sing-box `v1.13.11`(2026-04-23)、mihomo `v1.19.24`(2026-04-20)、clash-speedtest `faceair/clash-speedtest v1.8.3`(2026-02-05,Go 1.24,內嵌 mihomo)。

**動作**：
- [ ] **補 `anytls://`** 到 `CONFIG_RE` / parser / emit:總是 TLS 包裹、session-pool mux;emit 到 sing-box(`anytls` outbound)+ mihomo(kebab-case + uTLS/ECH),**verify 用 sing-box 不用 xray**。這是目前漏掉的 yield。
- [ ] **汰 SSR**:`parser` 仍解 `ssr://` 但產出趨零 → 降級/標記 deprecated(留解析、不投資)。
- [ ] TUIC 仍列一等目標,但實際極稀(Au1rxx 快照 tuic×1 vs trojan×1167)—— 降低期待。
- [ ] verify 升級評估:2026 領先聚合器(Au1rxx / LeilaoMi / rtwo2)已改用 **HTTP-over-proxy 204/200 探測**(per-node SOCKS5 inbound 打真 GET,2 輪 45s 取 ≥50%),比 clash-speedtest 純頻寬測更嚴。現行 `clash-speedtest` 仍有效可留,但把 HTTP-over-proxy 探測列為 Stage-4 verify 強化選項。
- [ ] 注意:Xray 近版加了 post-quantum(VLESS ML-KEM-768、REALITY ML-DSA-65)—— verify 用當前 Xray/sing-box build 以免 false-negative。

---

### 1.3 新增 2026 活躍 clearnet seed repos（canary 晉升,**非 gray**）✅

**2026 現況**：大量自動更新的聚合 repo 仍高產(皆 2026-07 有 commit):`Epodonios/v2ray-configs`(/5min)、`barry-far/V2ray-Config`(/15min)、`ebrasha/free-v2ray-public-list`(/15min)、`MatinGhanbari/v2ray-configs`(7500+ /15min)、`MohammadBahemmat/V2ray-Collector`、`0xRadikal/Free-v2ray-Configs`(/30min)、`MahanKenway/Freedom-V2Ray`、`LeilaoMi/AutoMergePublicNodes-Optimized`、`rtwo2/FastNodes`(158 源、~52k alive/6h、品質評分)。

**動作**：
- [ ] 把上述挑 3–5 個寫進 `state/candidates.jsonl`(`enabled:false`),走既有 **source-canary** 晉升門(mirror-Jaccard≥0.80、unsupported≤0.20、overlap≤0.90、3 runs/48h)。這是 clearnet 白管線,**零黑產風險**,是補節點量最快最安全的路。

---

### 1.4 A8 — CT + passive DNS（`ct_recon.py`）✅ 被動、低險

**2026 現況**：
- **crt.sh 仍在**(Sectigo,Postgres,500M+ 條目),`GET crt.sh/?q=<domain>&output=json` 可 scripting;但**速率限制未公開**、易過載、回應 3–30s、對 RU 偶爾要 VPN。守則:別對同域名每分鐘狂打。
- **CertSpotter(SSLMate)**:免費 CT search API,**免 key token 可程式化**,crt.sh 慢/被限時的**理想 fallback**。
- **Google / Cloudflare CT log**:免費、API 穩,可當第三來源。
- **SecurityTrails**:已被 **Recorded Future 併購($65M),現為其產品**;仍有受限免費層(每日查詢有限)+ 1B+ passive DNS。repo 的 `SECURITYTRAILS_API_KEY` 路徑仍可用,但認清它現在是 RF 產品、免費層很小。

**動作**：
- [ ] `ct_recon.py` 多源聚合:crt.sh(主)+ **CertSpotter(fallback)**,去重合併進 `state/recon_intel.jsonl`。
- [ ] `config/ct_watch.yaml` 把 placeholder `example.com` 換成真實 watch 目標。
- [ ] 認清定位:**這是 feeder(餵 `v2board_recon` 的候選 host / SNI),不是直接節點來源**。純被動、風險最低,但別期待它直接產節點。

---

### 1.5 A4 — GitHub code-dork（`github_dork.py`）✅ config 抓取有效 / 洩密只記錄

**2026 現況**：
- REST `GET /search/code` + `gh search code` 仍在,形態不變:**須認證**、`code_search` bucket **10 req/min**、單查 **1000 筆硬上限**(10 頁×100)、用 **legacy 語法**(Blackbird regex 只在網頁 UI,REST 不吐;`sort:indexed` 2023 已砍 → 無法按新鮮度排序)。`extension:` `filename:` `path:` 仍可用。
- **trufflehog v3.96.0**(~2026-07-24,AGPL-3.0,800+ detector,live 驗證)—— 健康,`trufflehog github --org=<org>` 照用。
- **gitleaks v8.30.1** 仍可用但**已 feature-complete / 只出安全補丁**;原作者 2026-02 推出後繼者 **Betterleaks**。現有 flags/`.toml` 仍有效,`gitleaks dir` 照舊;規劃日後遷 Betterleaks。
- **洩密向量已退化**:GitHub push protection + secret scanning 預設開、2025-2026 擴充(2025-11 base64 偵測、2026-06 更多 token 類型 + validity check、Public Monitoring 全站掃)→ 高價值新洩憑證多在 push 時就被擋或極短命(對手 ~5 分鐘內就收割)。

**動作**：
- [ ] **啟用 config-檔 dorking**(高產且低險):`vmess:// extension:txt`、`vless:// extension:txt`、`hysteria2:// extension:yaml`、`proxies: extension:yaml`(Clash)、`outbounds vless extension:json`(sing-box)、`filename:sub vmess`… 配合瀏覽 `github.com/topics/{vmess,vless,hysteria2}`(比 API 更可靠的新鮮度)。
- [ ] **洩密面板憑證維持 log-only**(`fetch_third_party_raw` 強制 false)—— 只記錄給人工 takedown,**絕不抓用第三方洩憑證**(越權存取 / CFAA 風險)。
- [ ] pacing 維持 `CODE_SEARCH_RATE_GAP=6.5s`(~9/min,安全);>1000 命中會被靜默截斷,log 出來別當「全覆蓋」。
- [ ] REST API version header 現為 `2026-03-10`(repo pin `2022-11-28` 仍可用,不急)。

---

## 2. recon-only 向量（W3,高摩擦、需人工把關）

### 2.1 面板搜尋引擎 Shodan / FOFA / Quake（`gray_sources.py`）

**2026 現況**：三家都活著、repo 指紋查詢仍有效,但**免費經濟與外國存取分歧巨大**,決定誰真的有產出:
- **FOFA(最推)**:~4B 資產、350k 指紋規則,favicon/FID pivot 最強;原生 `app="V2Board"` / `app="Xboard"` 指紋;**API 改 key-only**(舊 email+key 仍相容 → repo 的 `fofa_email+fofa_key` 還能跑);`en.fofa.info` **email 註冊即可,不強制中國手機** → 對非中國運營者最可及。免費 ~100 列後計費(F-points)。
- **Shodan**:語法不變,但**免費層 filter-gated** —— repo 每條查詢都帶 filter → 都要**付費 key**(Membership 一次性 $49;API Freelancer $69/mo 起)。免費槓桿:`/shodan/host/count`(**零 query credit**,拿母數/facets 很好用)、InternetDB(免帳號)。**JSON 格式 2025 改了**:facet 從 `{value,count}` → `[value,count]`(**parser 要修**)。對中國機場覆蓋最弱。
- **Quake(360)**:DSL 完整(`response:` `title:` `app:`),但**看中國境內資料需實名認證**(中國身分/手機)→ 外國 token 大幅少回結果。
- **Censys**:2025 砍掉免費 Search(Legacy 2025-03-31 停、v1/v2 API ~2025 底退役)→ **不再是免費 fallback**。

**動作**：
- [ ] **FOFA 優先**:V2Board/Xboard/SSPanel 多是中國機場,FOFA 覆蓋 + 原生指紋 + 可及性三者最佳。
- [ ] 修 `gray_sources.py` Shodan facet parser:適配 `[value,count]`;加免費 `host/count` 母數估算。
- [ ] favicon-hash 跨引擎:Shodan `http.favicon.hash` 與 FOFA `icon_hash` 都用 **mmh3**(可互通);Quake/Censys 不同(Censys=SHA-256)要各自重算。
- [ ] 產出**只當 discovery leads**(`gray_panel_leads.jsonl`,`approved=false`),餵 `v2board_recon` 指紋,**不自動註冊/收割**。註冊收割只對 `panel_register.approved_targets`(空)且 gate 開 + `PANEL_PASSWORD`。
- [ ] 缺 FOFA/Quake key 就 skip 該引擎(現行行為,保留)。

**風險**:三家 AUP 都禁把結果拿去未授權探測/存取;高量面板獵查對 provider 與面板主可見(Chinese-operated,查詢與帳號被記錄);索引落後 → 很多面板已死/是 honeypot/已被濫用,收割節點低信任。

---

### 2.2 A2 — V2Board/Xboard CVE-2026-39912（`v2board_recon.py`）

**2026 現況(已核實為真,非杜撰)**：
- **CVE-2026-39912**:NVD 2026-04-09 發布(2026-07-14 修訂),assigner **VulnCheck**,**CVSS 9.1 Critical**,CWE-201。影響 **V2Board 1.6.1–1.7.4**(已棄,上游不修)與 **Xboard ≤0.1.9**。發現者 Valentin Lobstein(Chocapikk),**公開 PoC**:`github.com/Chocapikk/CVE-2026-39912`。
- **利用鏈(已確認)**:`POST /api/v1/passport/auth/loginWithMailLink {email}` → 回應 body 洩 magic-link/verify token → `GET /api/v1/passport/auth/token2Login?verify=<TOKEN>` → `auth_data` Bearer + `is_admin:true` → `GET /api/v1/user/getSubscribe` → 訂閱 token + `subscribe_url`。
- **指紋端點屬實**:`GET /api/v1/guest/comm/config`(未授權 guest config)、`/api/v1/admin/config/fetch`(403 `鉴权失败` 是 V2Board-family oracle)。
- 部署量:ZoomEye ~7,124 實例(2,096 在 port 7001)/ Shodan ~557,集中 CN/HK/JP/SG/US。

**兩處需修正 repo 假設**：
1. **利用鏈只在 admin 手動開了非預設的 `login_with_mail_link_enable` 時才成立**(研究者明講「預設不開」)→ ~7,124 是**總數不是可利用數**,野掃真實 yield 遠低於文件暗示。
2. repo 寫「getSubscribe 回 base64 訂閱」是**下游細節、非 CVE 本身**:`getSubscribe` 回的是 `subscribe_url`(一個 URL),base64 節點 blob 是你**後續 fetch 那個 URL** 才出現。碼/文件要更正。
3. patch 現況:**Xboard 已修**(PR #873 / commit `121511523…`,改回 `[true,true]`,fork 活躍維護)→ 可利用面逐步縮小、集中在**已棄的自架 V2Board**;V2Board PR #981 只是文件(專案已棄不修)。CISA-ADP SSVC:exploitation=poc、automatable=yes。

**動作(嚴守授權界線)**：
- [ ] **野生面板只做指紋**(recon):`guest/comm/config` + `admin/config/fetch` 403 oracle → 寫 `recon-leads.jsonl`,**不對野生面板送利用鏈**。
- [ ] **完整 ATO 利用鏈只跑 `config targets`(自有/授權,現為空)** → `gray_nodes.jsonl` tier=black、`enabled:false`、`watermark_suspect:true`。這是現行碼的正確姿態,保留。
- [ ] 更正碼/文件的 base64 誤解(getSubscribe → subscribe_url → 再 fetch → base64)。
- [ ] 若要實測利用鏈:**自建 V2Board/Xboard honeypot-lab 授權標的**,只在自有基礎設施上驗證。

**風險**:對非自有面板跑完整 ATO 鏈 = 未授權存取 + 帳號接管(CFAA / 電腦濫用法),遠高於指紋的法律風險;公開 PoC + CISA 收錄 → defenders/honeypot 正盯這些端點;面板主用 per-account 浮水印訂閱 token 追蹤/封鎖 scraper;可利用面隨 Xboard 修補縮小。

---

## 3. drop / 封存向量

### 3.1 G2 — 公網端口掃描（`scanner.py`）⚠️ degraded → drop

**2026 現況**：工具本身當前(nmap 7.99 / 2026-03-26;masscan 維護中,2024-12 加 TLS-1.3 cert banner),`masscan → nmap -sV` 對授權 allowlist 可跑。**但向量目的(無差別掃描找可用免費節點)在 2026 基本失效**:
- 現代可用協定**設計上抗探測**:VLESS+Reality 把無憑證探測轉發到真 SNI 上游、回傳該站真憑證 → 掃描器看到的是正常 HTTPS,**沒有 proxy「破綻」**;Trojan/VLESS-TLS 對無 token 連線與 HTTPS 無異。
- hysteria2/tuic 走 **UDP/QUIC,masscan TCP SYN 掃不到**(`scanner.py` 已只記 UDP lead)。
- **掃得到的只有配置錯誤/遺留節點**(裸 SS on 8388、無 TLS VMess)—— 正是 GFW 已偵測/封鎖的(Trojan ~90%、VMess ~80% 偵測率,post-2025)→ **掃得到 ≈ 快死、低值**。
- 且掃到也不能用:免費節點需**帶外(subscription/GitHub/TG)分發的憑證**(UUID/密碼/MTProto secret),**掃描無法還原**。
- Hosting AUP 對第三方主機大規模掃描「一律明禁」(AWS/Vultr/DigitalOcean 保留停權;Vultr 稱通報執法);單 VPS rate=10000 SYN/s 極易被 IDS 標記。

**動作**：
- [ ] 標記 `scanner.py` **deprecated**,維持 `enabled:false` / `leads_only:true` / IP allowlist,**不再投資**。既有 credential-guess 重建路徑維持 gate + quarantine + 人工審核。
- [ ] 若未來真要「掃」,方向是 **QUIC-aware 探測(JA3/JA3S)** 針對授權標的,而非 masscan/nmap 無差別 —— 但 CP 極低,列為最低優先。

---

## 4. 跨向量安全模型（不放寬,重申）

- 所有 gray/black 向量 **預設 `enabled:false`**;非 `all` 管線的一部分,獨立命令。
- gray 輸出一律隔離:`gray_nodes.jsonl` 須同時 `enabled==true && watermark_suspect==false` 才會被 `resin_publisher` 發佈;純 URI 行、缺欄位 = 未審核,丟棄。
- **利用只對自有/授權標的**(`config targets`);野生面板只指紋。
- SSRF 防護(`gray_sources._validate_public_url`,`v2board_recon` 復用)保留:拒 localhost/私有/保留/非全域 IP、擋 TLS 降級 redirect、每個 redirect hop 重驗 DNS。
- fail-closed:空/壞結果永不覆寫上一份好快照。
- gray/black 與生產發佈**分流**:走 `publish-resin`(本地 resin sticky-proxy),**不進** Cloudflare Worker 生產訂閱。
- 合規備註:CF ToS §2.2.1(j) 禁在 Workers 跑 VPN/proxy;gray/black 運營風險高 → 這也是全預設關的原因。

---

## 5. 落地路線圖（波次)

**W1（低險、高產、純自有/clearnet)**
1. 協定升級:補 AnyTLS parser/emit、汰 SSR、TUIC 降期待。
2. 新增 3–5 個 2026 活躍 seed repos 走 canary 晉升。
3. `tg_recon.py`:改原生 `data-before` cursor、補活躍頻道、維持隔離審核。

**W2（gated feeder、低險)**
4. `ct_recon.py`:加 CertSpotter fallback、多源合併、換掉 placeholder watch。
5. `github_dork.py`:啟用 config-檔 dorking(洩密維持 log-only)。

**W3（recon-only、需付費帳號/人工把關)**
6. `gray_sources.py`:FOFA 優先、修 Shodan `[value,count]` parser、加免費 host/count、favicon mmh3 跨引擎;產出只做 leads。
7. `v2board_recon.py`:野生只指紋;ATO 鏈只對自有授權標的;更正 getSubscribe→subscribe_url 誤解。

**封存**
8. `scanner.py`:標 deprecated、維持關閉、不投資。

---

## 6. 待你決定

1. **面板引擎付費**:FOFA(推,email 註冊)vs Shodan($49 一次性 Membership)—— 要開哪個帳號?（不開就 W3 面板向量空轉）
2. **A2 實測**:要不要自建 V2Board/Xboard honeypot-lab 授權標的來驗利用鏈?(唯一合規用法)
3. **AnyTLS 現在就補**嗎?(sing-box/mihomo 支援、Xray 不支援 → verify 走 sing-box)
4. **波次順序**確認 / 調整。
5. Quake 幾乎對外國 token 無用(需中國實名)—— **直接放棄 Quake、只留 FOFA+Shodan**?

---

## 附錄 — 關鍵引用（一手來源）

- CVE-2026-39912：<https://nvd.nist.gov/vuln/detail/CVE-2026-39912> · VulnCheck advisory · Chocapikk writeup `chocapikk.com/posts/2026/xboard-v2board-account-takeover/` · PoC `github.com/Chocapikk/CVE-2026-39912` · Xboard fix `github.com/cedar2025/Xboard/pull/873`
- 搜尋引擎經濟/存取：`book.shodan.io/release-notes/2025/`（JSON `[value,count]`、host/count 免費）· Censys legacy 退役 `censys.com/blog/legacy-search-deprecation/` · FOFA key-only `x.com/fofabot/status/1737740004376674475`
- Telegram：`dev.to/.../how-to-scrape-telegram-channels-in-2026` · Telethon `pypi.org/project/Telethon/`（1.44.0）· Kurigram `github.com/KurimuzonAkuma/kurigram` · TGParse `github.com/Surfboardv2ray/TGParse`
- GitHub dork：`docs.github.com/en/rest/search/search`（10/min、legacy）· trufflehog `github.com/trufflesecurity/trufflehog/releases`（v3.96.0）· gitleaks feature-complete + Betterleaks `appsecsanta.com/gitleaks`
- 端口掃描/協定：GFW active probing `gfw.report/publications/imc20/en/` · QUIC/SNI `gfw.report/publications/usenixsecurity25/en/` · VLESS-Reality `deepwiki.com/crazypeace/xray-vless-reality` · nmap `nmap.org/changelog.html`
- 生態/核心：`cuanmu.com/blog/proxy-protocols-comparison-2026/` · cores `core-tutorial.argsment.com` · clash-speedtest `github.com/faceair/clash-speedtest/releases`（v1.8.3）· 活躍 repos `github.com/topics/v2ray-config?o=desc&s=updated`
- CT/passive DNS：crt.sh JSON `crt.sh/?q=<domain>&output=json` · CertSpotter(SSLMate)免 key token · SecurityTrails→Recorded Future 併購（$65M）
