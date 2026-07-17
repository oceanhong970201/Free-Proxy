# 訂閱輸出（自動產物）

`output/` 由 aggregator 產生並可由 CI 提交。請勿直接編輯產物；若格式有誤，修正 parser/emitter、重新驗證，再重建完整 snapshot。

## 檔案

| 檔案 | 格式 | 典型讀取端 |
|---|---|---|
| `clash.yaml` | Clash/Mihomo YAML | Mihomo 相容客戶端 |
| `singbox.json` | sing-box JSON | sing-box 相容客戶端 |
| `v2ray-base64.txt` | 換行 URI 經 UTF-8 base64 | 支援 V2Ray subscription 的客戶端 |
| `feed.xml` | RSS 2.0 | RSS reader／更新監控 |
| `pipeline-status.json` | Sanitized schema v1 JSON | 遠端 Dashboard／狀態監控 |
| `_headers` | 靜態託管 response headers | Pages 類靜態託管 |

不同客戶端 schema 並不保證支援完全相同的協議與 transport。對目標 client 明確不支援的協議，emitter 只能使用有測試的顯式 skip，並在 summary 回報原因與數量；這也是 `singbox.json` 節點數可能少於其他格式的原因。損壞的 live 記錄、必要欄位缺失、未知 transport 或其他非預期轉換錯誤會使正常 emit 失敗並保留上一份五檔 snapshot，不會靜默降級成 TCP 或發布半寫檔案。

## 產生條件

正常發布流程為：

```text
fetch -> parse -> verify -> emit -> publish --strict
```

- `emit` 只使用 `alive is True` 的完整代理設定。
- `publish --strict` 再要求達到 `config/quality.yaml` 的下載速度門檻。
- 合格節點為空時保留既有輸出與 Worker snapshot。
- 檔案先寫至暫存檔，再以 replace 更新，避免單檔半寫。
- GitHub Actions schedule 是 best-effort；cron 設定不保證準點或一定執行。以 workflow run 結果與產物 commit 時間判定新鮮度。

## 重建

只有在 `state/live.jsonl` 已由本輪完整 verify 更新後才執行：

```powershell
python src\aggregator\cli.py emit
```

不要用舊的、未驗證的或手工修改過的 `state/live.jsonl` 覆蓋 tracked output。

## 離線完整性檢查

以下檢查格式可解析、base64 可解碼及檔案非空；客戶端語意驗證仍需使用對應程式：

```powershell
@'
from pathlib import Path
import base64, json
import xml.etree.ElementTree as ET
import yaml

root = Path("output")
clash = yaml.safe_load((root / "clash.yaml").read_text(encoding="utf-8"))
singbox = json.loads((root / "singbox.json").read_text(encoding="utf-8"))
decoded = base64.b64decode(
    (root / "v2ray-base64.txt").read_text(encoding="utf-8"),
    validate=True,
).decode("utf-8")
ET.parse(root / "feed.xml")

assert isinstance(clash, dict) and isinstance(clash.get("proxies"), list)
assert isinstance(singbox, dict) and isinstance(singbox.get("outbounds"), list)
uris = [line for line in decoded.splitlines() if line.strip()]
assert uris
print({"clash": len(clash["proxies"]), "singbox": len(singbox["outbounds"]), "uris": len(uris)})
'@ | python -
```

若本機已安裝對應 client，再執行：

```powershell
sing-box check -c output\singbox.json
# 依本機 Mihomo/Clash binary 的參數檢查 output\clash.yaml
```

## 發布 URL 範本

下列只是 URL 形式，不代表對應服務目前已部署或最新一次 workflow 成功。

### GitHub Raw

```text
https://raw.githubusercontent.com/OWNER/REPO/BRANCH/output/clash.yaml
https://raw.githubusercontent.com/OWNER/REPO/BRANCH/output/singbox.json
https://raw.githubusercontent.com/OWNER/REPO/BRANCH/output/v2ray-base64.txt
https://raw.githubusercontent.com/OWNER/REPO/BRANCH/output/feed.xml
```

### jsDelivr

```text
https://cdn.jsdelivr.net/gh/OWNER/REPO@BRANCH/output/clash.yaml
https://cdn.jsdelivr.net/gh/OWNER/REPO@BRANCH/output/singbox.json
https://cdn.jsdelivr.net/gh/OWNER/REPO@BRANCH/output/v2ray-base64.txt
https://cdn.jsdelivr.net/gh/OWNER/REPO@BRANCH/output/feed.xml
```

CDN 可能有大小、快取與 purge 限制；workflow 中的 purge 成功也不能取代內容驗證。

### Cloudflare Pages 或其他靜態站

```text
https://YOUR_STATIC_SITE/clash.yaml
https://YOUR_STATIC_SITE/singbox.json
https://YOUR_STATIC_SITE/v2ray-base64.txt
https://YOUR_STATIC_SITE/feed.xml
```

只有在 deployment workflow 成功且對應 commit 已上線後，才把此 URL 對外標為可用。

## Worker 訂閱與靜態檔的差異

Worker `/sub` 與 `/sub?format=clash` 讀取 D1 中目前完整 snapshot；靜態 URL 讀取 repository／Pages 上一次成功提交的 `output/`。兩者可能因部署順序而短暫不同，維護時應比對：

- 最近 strict publish 的 `snapshot_id` 與節點數；
- output commit SHA；
- Worker `/health` 的 `ok`、snapshot counts 與 age；
- Pages/CDN 實際回傳內容的 hash。

RSS channel link 使用 `PUBLIC_BASE_URL`；若未設定，應在發布前確認預設值是否適合目標環境。

## Public pipeline status

`pipeline-status.json` is a sanitized, fixed-schema snapshot for operational
dashboards. Schema version 1 contains only `generated_at`, `pipeline_status`,
verification counts, and emitted artifact counts. It never contains proxy URIs,
credentials, tokens, provider responses, or verification error details.

The tracked bootstrap state may be `unknown` with `verify.completed: false`.
Only a successful `verify -> emit` run can atomically replace it with `healthy`;
a failed run retains the previous public status and subscription snapshot.
