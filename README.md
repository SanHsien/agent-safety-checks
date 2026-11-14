# agent-safety-checks

給 AI agent 用的本機安全檢查工具集：採納第三方技能包前掃描、工具呼叫審批驗證、截圖隱私判斷、本機憑證與持久化稽核。全部只用 Python 標準函式庫，不連網、不執行被檢查的內容。

> 這些都是**啟發式靜態檢查**。通過不等於安全，只代表「沒踩到已知樣式」。各工具抓不到的東西見下方「能力邊界」。

## 各工具在 agent 工作流程的哪個時間點使用

```
 採納第三方技能包 ──► 派工／執行工具呼叫 ──► 截圖或 OCR ──► 定期稽核本機
        │                      │                    │                │
        ▼                      ▼                    ▼                ▼
 verify_agent_skill_    verify_tool_call_    screen_privacy.py   audit_oauth_credentials.py
 pack_safety.py         firewall.py          (截圖前：視窗分類    verify_cloud_persistence_
 (--pack <目錄>)        (審批收據＋請求      截圖後：OCR 洩鑰)    audit.py
                         雜湊；trace 去重)                        (持久化／帳號／MCP 憑證)
```

## 工具表

結束碼是逐支實跑 `--help` 與各種輸入（通過、命中、錯誤路徑）核對過的結果，不是照抄 docstring。

| 指令 | 用途 | 結束碼 |
|------|------|--------|
| `python tools/verify_agent_skill_pack_safety.py --pack <目錄>` | 採納前靜態掃描技能包（可重複 `--pack`；另有 `--strict`、`--json`、`--max-bytes`、`--ack-unscanned`；`--config`／`--self-test` 只檢查自述宣告，不能當採納依據） | 0 通過；1 有 FAIL（`--strict` 時 REVIEW 也算）；2 輸入錯誤或無法掃描（裸執行、目錄不存在或為空、有未掃描檔且未確認） |
| `python tools/verify_tool_call_firewall.py --verify-calls <json>` / `--analyze-trace <json>` | 驗證工具呼叫的單次審批收據與請求雜湊；分析 Agent trace 的 span 去重耗時與 token | 0 全部通過；1 有呼叫被拒，**或檔案不存在**；2 沒給參數，或 JSON／schema 無效 |
| `python tools/verify_cloud_persistence_audit.py --scan-dir <目錄>` / `--scan-run-keys` / `--audit-accounts-json <json>` / `--audit-mcp-config <json>` | 本機竊密木馬特徵檔名、Windows Run keys、雲端 Service Account 異常、MCP 設定寫死的憑證 | 0 所選檢查未命中；1 規則命中；2 輸入或讀取失敗、沒選任何檢查，或所選檢查全被跳過（例如非 Windows 只選 `--scan-run-keys`） |
| `python tools/audit_oauth_credentials.py [--home DIR] [--dir DIR] [--repo DIR] [--strict] [--json]` | 本機 AI 工具 OAuth 憑證檔放置是否安全（位置、權限／ACL、git 狀態、監聽位址）；只讀 metadata，不輸出 token | 0 通過（只有 WARN／INFO）；1 有 ERROR，或 `--strict` 且有 WARN；2 參數錯誤或 `--home` 目錄不存在 |
| `python tools/screen_privacy.py --title <標題> [--app <exe>]` / `--ocr-file <txt>` | 截圖前判斷視窗類別（`blocked`／`self`／`nocap`／`ok`）；截圖後判斷 OCR 文字要不要丟圖，並輸出脫敏文字 | 0 執行成功（**判斷結果在 stdout，不在結束碼**：`blocked` 與 `action: drop_image` 也回 0）；2 沒給 `--title`／`--ocr-file`、或讀不到 OCR 檔 |

呼叫端必須讀 `screen_privacy.py` 的 stdout（`classification:`、`action:`），不能只看結束碼。

## 快速開始

需要 Python 3.11 以上，不需安裝任何套件。

```bash
# 採納前掃描第三方技能包
python tools/verify_agent_skill_pack_safety.py --pack path/to/skill-pack
echo $?    # 0 才算掃描完整且無 FAIL；REVIEW 項目仍要人工看

# 截圖前
python tools/screen_privacy.py --title "視窗標題" --app chrome.exe
# 截圖後
python tools/screen_privacy.py --ocr-file ocr.txt

# 本機憑證放置稽核
python tools/audit_oauth_credentials.py --strict

# 跑測試（不要設 PYTHONUTF8，CI 刻意用系統預設編碼）
python -m unittest discover -s tests
```

截圖隱私規範全文：[docs/multimodal-screen-privacy-spec.md](docs/multimodal-screen-privacy-spec.md)（正則常數以程式為準）。

## 能力邊界（抓不到什麼）

### verify_agent_skill_pack_safety.py
- 執行期才組出來的內容：變數間接（最多 REVIEW）、字串拼接出的旗標、從檔案或環境變數讀進來的參數。
- 編碼與混淆：base64、十六進位、壓縮檔、被壓縮混淆的 JavaScript；只有 PowerShell 編碼指令與「解碼後接管線」會標 `OBFUSCATED`。
- 不經管線的遠端執行：`npx`／`uvx`／`pipx run`、`pip install git+https://…`、`mshta`、`certutil -urlcache`、程式內用 HTTP 函式庫下載再執行。
- 二進位與壓縮檔（`.zip`、`.dxt`、執行檔、圖片）只列為未掃描；技能包以外的東西（相依套件、執行期下載的程式、遠端 MCP 伺服器行為）不在範圍。
- 不靠危險旗標的攻擊：提示詞注入、合法指令濫用、規則表沒列的憑證路徑、資料外傳。
- 旗標清單會過期；YAML frontmatter 只認區塊式寫法（標準庫沒有 YAML 解析器）。
- 宣告模式（`--config`、`--self-test`）檢查的是填寫者自述，無法驗證真偽。
- 細節與來源見 [ai-inbox 的技能包審計文件](https://github.com/SanHsien/ai-inbox/blob/main/docs/claude-code-domain-skill-packs-and-mcp-audit.md)。

### verify_tool_call_firewall.py
- 審批收據只是請求內容的 SHA-256 雜湊，**沒有簽章**：任何能呼叫 `issue_approval_receipt` 的人都能自己造收據。它防的是「審批後內容被改」與「同一張收據重放」，不防偽造審批。
- 單次使用只在單次執行（單一行程、單一批次檔）內記錄，不跨行程持久化。
- 只認內建的五種工具名稱與各自的欄位白名單；路徑只做邏輯檢查，不確認實體檔案系統上的符號連結。
- trace 分析是算術去重，不判斷 span 內容是否可信。

### verify_cloud_persistence_audit.py
- 離線啟發式，不判定感染，也不判定帳號授權是否合法。
- `--scan-dir` 只比對已知檔名清單，不自動發現 LaunchAgents／Startup；改名的木馬抓不到。
- 帳號資料的 `createTime` 要由外部補入（IAM v1 匯出本身沒有），`has_user_managed_keys` 不是遠端金鑰查證。
- MCP 檢查不是完整 schema 驗證；只豁免完整的 `${VAR}`、`$VAR`、`%VAR%`、`{{VAR}}`、`<VAR>` 佔位符；憑證樣式只比對固定幾種前綴與鍵名。

### audit_oauth_credentials.py
- 只看 metadata，不驗證 token 是否仍有效。
- 無 BOM 的 UTF-16 若以非 ASCII 字元為主，或無 BOM 的 UTF-32，會被當 UTF-8 而**漏報**。
- 預設只掃各目錄第一層與 `oauth-proxy/`，不遞迴；只認 Grok CLI、Codex、Claude Code 的預設位置，其他工具要用 `--dir` 指定。
- Windows ACL 靠 `icacls`，git 狀態靠 `git`；不在 PATH 時降為 INFO，不會失敗。

### screen_privacy.py
- 只實作純文字、跨平台的兩層：視窗標題分類與 OCR 文字檢查。第二層（Windows UIA 無障礙樹探測）需要 COM，**未提供實作**。
- 看不到像素：圖片本身（未經 OCR 的畫面、手寫、截斷的金鑰）不在範圍；OCR 錯字會讓金鑰比對漏掉。
- 標題黑名單與機密正則是有限清單，新服務或新金鑰格式要有人加規則。
- 結束碼不反映判斷結果，見上方工具表。

## 與 ai-inbox 的關係

這些工具原本在 [SanHsien/ai-inbox](https://github.com/SanHsien/ai-inbox) 內開發，後來用 git-filter-repo 切出獨立 repo，**保留原本的 git 歷史**（commit 訊息與 docstring 裡的 `T-2026…` 編號是 ai-inbox 當時的任務編號）。文件裡指向仍留在 ai-inbox 的檔案，一律是 `https://github.com/SanHsien/ai-inbox/blob/main/...` 絕對網址。

後續工作與刻意不做的事見 [ROADMAP.md](ROADMAP.md)；開發規則見 [AGENTS.md](AGENTS.md)。

## 授權

MIT，見 [LICENSE](LICENSE)。
