# Project Status & Maintenance Guide

> Last updated: 2026-07-15
> 維護用速查：當前架構、運作流程、關鍵決策、已知問題、操作指引。

---

## 1. 一句話現況

AI 驅動免費 proxy 節點聚合器。GitHub Actions 每 30 分鐘從 au1rxx 倉庫拉節點 → 兩層測速 → 只推 ≥5MB/s 的進 Cloudflare Worker D1 → `/sub?format=clash` 吐排序好的活節點。Clash Verge 直接訂閱。

**訂閱 URL**（直接可用）：
```
https://proxy-sub-aggregator.proxy-aggregator.workers.dev/sub?format=clash
```
- `/sub` → v2ray base64
- `/sub?format=clash` → clash YAML
- `/health` → `{ok, ts}`

當前 /sub 約 **47–68 個節點**（Tier2 ≥5MB/s 驗證，隨節點狀態浮動）。

---

## 2. 架構

```
[au1rxx GitHub repo]
        │ fetch (CI, 每 30min)
        ▼
[GitHub Actions ubuntu runner]
   fetch → parse → emit → verify → publish --strict
                                  │
                                  ▼
                    [Cloudflare Worker] /admin/import (X-Admin-Token)
                                  │
                                  ▼
                       [D1 SQLite] nodes {uri, alive, latency, download_speed}
                                  │
                                  ▼
                          [/sub?format=clash]  ← Clash Verge 訂閱
                          (KV cache 60s)
```

| 元件 | 在哪 | 角色 |
|---|---|---|
| GitHub Actions | `oceanhong970201/Free-Proxy` (public) | fetch + verify + publish，無限免費分鐘 |
| Worker | `proxy-sub-aggregator.proxy-aggregator.workers.dev` | 訂閱服務（D1 + KV） |
| D1 | `nodes-db` (id `1b837756-1913-43e7-b727-2d5a23bb8a78`) | 節點存儲 |
| KV | `proxy-sub-aggregator-CACHE` (id `a8cc252082fc4736b5e9ce897cd33f37`) | /sub render cache 60s |
| 本地 resin | `localhost:2260` (Docker) | 本地代理池（可選，CI 連不到） |

---

## 3. 來源（state/sources.json）

| id | format | enabled | 備註 |
|---|---|---|---|
| `au1rxx-clash` | clash | ✅ tier 1 | 主力，台灣維護者，持續更新 |
| `au1rxx-singbox` | singbox | ✅ tier 1 | 同源 |
| `au1rxx-v2ray` | v2ray | ✅ tier 1 | 同源 |
| `vpnsuper-feed` | vpnsuper | ❌ disabled | supx_v1 私有 trojan，mihomo 連不上（0/3945 alive），代碼保留 |
| barryfar/epodonios/nomorewalls/snakem982 | — | ❌ dropped | 存活率 0–11% |

**只有 au1rxx 啟用。** 加新 source：在 sources.json 加 entry（`format=vpnsuper` 走專屬 harvester，其餘走 HTTP fetch + parser）。

---

## 4. CI Workflows（.github/workflows/）

| workflow | cron | 內容 | timeout |
|---|---|---|---|
| `fetch-and-publish` | `*/30 * * * *` + manual | fetch→parse→emit→verify→re-emit→publish --strict→commit→Pages→purge CDN | 45min |
| `verify-daily` | `17 5 * * *` + manual | 完整 verify + strict publish（保險） | 300min |
| `health-check` | — | Worker 健康檢查 | — |
| `tg-recon` | 6h | TG web-preview recon | — |

**注意**：GitHub 對 `*/30` schedule 會節流到實際 ~2 小時一次（public repo 也一樣）。要更密得手動觸發。

### verify 邏輯（src/aggregator/cli.py `_verify_logic`）
1. **TCP pre-filter**（`tcp_prefilter.py`）：async connect 443（concurrency 200, 3s），8 秒測完，砍 port 不通
2. **Tier1**：`clash-speedtest -fast`，latency <1000ms 算 alive
3. **Tier2**：`clash-speedtest -speed-mode download`，下載 ≥5MB/s 才通過
4. **resume**：`state/verify-progress.json`（fingerprint + tier1_idx + reachable + tier2_tested_hps），大節點集可分段
5. **`--max-runtime N`**：graceful pause，跑滿 N 秒存 progress 退出，下次 resume
6. **fresh start 清 DB**：`UPDATE nodes SET alive=NULL`，避免舊 alive 污染

### publish 邏輯（`_publish_logic`）
- `--strict`：只推 alive=True 且 download_speed ≥5MB/s
- strict 選出 0 → fallback non-strict（避免 /sub 空）
- base64 URI 清單 → POST Worker `/admin/import`

---

## 5. Worker（src/worker/sub-aggregator.ts）

端點：
- `GET /health` → `{ok, ts}`
- `GET /sub` → base64 v2ray 訂閱（KV cache 60s）
- `GET /sub?format=clash` → clash YAML（每 URI 重建 proxy dict）
- `POST /admin/import`（X-Admin-Token）→ upsert 節點

**clobber fix**：import 前先 `UPDATE nodes SET alive=0`，再 INSERT 新 snapshot 為 alive=1。避免上一輪死節點 linger。

**uriToClashDict** 支援：vmess（base64 JSON）、vless/trojan（URL parse）、ss（SIP002 regex + decodeURIComponent + base64 userinfo）。trojan/vless 帶 `allowInsecure=1` → `skip-cert-verify: true`。

部署：
```bash
cd src/worker
npx tsc --noEmit           # 型別檢查
npx wrangler deploy
```

---

## 6. 安全（重要）

- **repo 是 public** → Actions 分鐘無限免費。代碼無 secret（全 env-only）。
- **ADMIN_TOKEN**（Worker）：已輪換。存 Cloudflare Worker secret + GitHub secret。舊值（`JnLvqRyW...`）已失效。
- **RESIN_ADMIN_TOKEN / RESIN_PROXY_TOKEN**：env-only（.env / GitHub secret），無 hardcoded default。
- **CF_API_TOKEN / CF_ACCOUNT_ID / CF_PROJECT_NAME**：GitHub secret，未進 repo。
- ⚠️ **舊 secret 值仍在 git history**（已輪換失效 / 低價值 image 預設）。要徹底清可跑 `git filter-repo`，但通常輪換就夠。
- `.env`、`.admin_token.tmp`、`state/last-run.json`、`state/verify-progress.json` 全 gitignore。

輪換 Worker token：
```bash
TOK=$(python -c "import secrets; print(secrets.token_urlsafe(36))")
cd src/worker && echo "$TOK" | npx wrangler secret put ADMIN_TOKEN
gh secret set ADMIN_TOKEN -b "$TOK"
```

---

## 7. 關鍵決策記錄

| 決策 | 原因 |
|---|---|
| repo 改 public | private 額度 2000min/月，verify 用量 306min/天 7 天爆；public 無限 |
| 只保留 au1rxx | 其他 source 存活率 0–11%，au1rxx 27% |
| vpnsuper disabled | supx_v1 私有 trojan，mihomo/clash-speedtest/Clash Verge 連不上（0/3945），但 sing-box/xray 可能可用 |
| verify 在 CI 不在本地 | CI ubuntu 網路好，測得比本地 windows 準 4 倍（68 vs 16 alive） |
| TCP pre-filter | 砍 port 不通的，比 clash-speedtest 便宜 50 倍 |
| publish --strict + fallback | 高質量優先（≥5MB/s），但 strict 0 時 fallback 防止 /sub 空 |
| clobber fix（import 前清 alive） | 避免死節點跨輪 linger |
| parse 前清 DB nodes | 避免 dropped source + 過時 URI 累積污染 |

---

## 8. 已知問題 / Gotchas

- **GitHub 節流 schedule**：`*/30` 實際 ~2h 一次。要密就得手動觸發。
- **CI commit push race**：手動 push 跟 CI auto-commit 撞 → CI run fail（push rejected）。無害（publish 已成功）。避免：別在 CI run 進行中 push code。
- **ss SIP002 password**：base64 userinfo 可能 URL-encoded（`%3D`），Worker 要先 `decodeURIComponent` 再 base64 decode。
- **clash-speedtest 名稱映射**：emit_clash 加 dedup suffix，verify 用 `_lookup_hp` 帶 strip suffix fallback。
- **btoa UTF-8 限制**：Worker 用 TextEncoder/TextDecoder（非 btoa/atob）處理 CJK/emoji 節點名。
- **mihomo 不相容 supx_v1**：vpnsuper 節點對 Clash Verge useless，只能 sing-box/xray。

---

## 9. 維護操作

### 手動觸發 CI verify + publish
```bash
gh workflow run fetch-and-publish --ref master
gh run list --workflow=fetch-and-publish --limit 1   # 看結果
```

### 本地跑一次 pipeline（驗證用）
```bash
python src/aggregator/cli.py fetch
python src/aggregator/cli.py parse
python src/aggregator/cli.py emit
python src/aggregator/cli.py verify --max-runtime 540   # 分段
python src/aggregator/cli.py publish --strict   # 需設 ADMIN_TOKEN env
```

### 確認 /sub 狀態
```bash
curl -s https://proxy-sub-aggregator.proxy-aggregator.workers.dev/health
curl -s "https://proxy-sub-aggregator.proxy-aggregator.workers.dev/sub?format=clash" -o clash.yaml
grep -c 'type:' clash.yaml   # 節點數
```

### 加新 HTTP source
在 `state/sources.json` 加 entry（format: clash/singbox/v2ray）。下次 CI 自動拉。

### 加 vpnsuper 類（多檔+解密）source
寫 harvester 模組（參考 `vpnsuper_feed.py`），在 `fetcher.fetch_all` 加 `format` 分派。

### 重新部署 Worker（改碼後）
```bash
cd src/worker && npx tsc --noEmit && npx wrangler deploy
```

---

## 10. 關鍵檔案

| 檔案 | 角色 |
|---|---|
| `src/aggregator/cli.py` | 12+ 命令 CLI（fetch/parse/verify/emit/publish...） |
| `src/aggregator/fetcher.py` | source fetch + vpnsuper 分派 |
| `src/aggregator/parser.py` | URI/clash/singbox 解析 + node_to_uri |
| `src/aggregator/emit.py` | live.jsonl → clash.yaml/singbox.json/v2ray/rss |
| `src/aggregator/tcp_prefilter.py` | async TCP 443 connect gate |
| `src/aggregator/vpnsuper_feed.py` | VPN Super GitHub feed 解密 harvester（disabled） |
| `src/worker/sub-aggregator.ts` | Cloudflare Worker（訂閱服務） |
| `config/quality.yaml` | verify 參數（max_latency, min_dl, concurrent, top_n） |
| `state/sources.json` | 來源清單（enabled/tier） |
| `.claude/hooks/stop-check.sh` | stop hook（看 CI 新鮮度） |

---

## 11. 近期 commit

- `898ddd2` security: rotate leaked secrets + remove hardcoded literals (repo public)
- `2486213` ci: don't git-add gitignored state files
- `d5eaf08` verify: TCP pre-filter + resume + max-runtime; trojan skip-cert-verify; fix DB stale rows
- `cc67844` add vpnsuper GitHub-feed harvest channel
- `b107e86` fetch.yml: add per-run verify + strict publish; fix D1 clobber bug

---

## 12. 下一步可選

- [ ] 補 self_nodes.yaml（自有 VPS）→ publish-self 進 resin
- [ ] vpnsuper 改接 sing-box/xray client（若要用那 3766 節點）
- [ ] git history 清舊 secret（`git filter-repo`，非必要，已輪換）
- [ ] 填 Shodan/FOFA/Quake key → 解鎖面板指紋掃 gray 渠道
- [ ] 填 TG credentials → 解鎖 MTProto 深歷史爬取
- [ ] 調 verify 頻率/參數（config/quality.yaml）