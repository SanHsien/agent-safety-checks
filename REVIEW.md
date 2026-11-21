# REVIEW.md

> latest-only：只留最近一次覆核。修好的項目回註修復 commit 與日期（艦隊協作約定）。
> 嚴重度：**高**＝可直接繞過或造成程式碼執行；**中**＝常見情境下漏報、或結束碼放行；**低**＝邊角情況、效能或契約不一致。

## 2026-11-21 攻擊者角度覆核（四支工具）

範圍：`verify_tool_call_firewall.py`、`verify_cloud_persistence_audit.py`、`audit_oauth_credentials.py`、`screen_privacy.py`（含 `docs/multimodal-screen-privacy-spec.md`）。技能包掃描器同日已另行覆核（`2bb61fc`、`6ade62b`、`c2d1f13`），不在本次範圍。

做法：讀程式找邏輯缺陷、構造對抗樣本實測修前判定、每個缺陷先寫會紅的測試再修、對每個修正做 mutation（改壞後確認測試會紅）、拿本機真實無害資料比對修前修後的誤報數。

### verify_tool_call_firewall.py

| 編號 | 嚴重度 | 樣本 | 修前 | 修後 | 修復 |
| --- | --- | --- | --- | --- | --- |
| F-1 | 中 | 驗證檔的 call 有重複鍵：`"path":"../../evil","path":"src/a.py"` | 取最後一個值、`ALLOWED`、結束碼 0；取第一個值的執行端會寫到審批沒看過的路徑 | 任何物件有重複鍵回 2 | `a3a6a1f`（2026-11-21） |
| F-2 | 低 | `src/CONIN$`、`src/conout$`、`src/COM0`、`src/LPT0`、`src/COM¹`～`³` | `ALLOWED` | `UNSAFE_PATH` | `a3a6a1f`（2026-11-21） |
| F-3 | 中 | `src/．．/．．/x`（全形句點）、`src/a∕..∕x`、`src/¥..¥x`、`src/a：b` | `ALLOWED`；執行端若走 Windows ANSI API，best-fit 會轉成 `../` 越界 | `UNSAFE_PATH` | `a3a6a1f`（2026-11-21） |
| F-4 | 低 | `src/a\x00b`、`src/a\tb`、`src/x*`、`src/a"b`、孤立代理字元 | `ALLOWED`（NUL 會被 C 執行端截斷、`*` 會被 shell 展開） | `UNSAFE_PATH` | `a3a6a1f`（2026-11-21） |
| F-5 | 低 | 20 萬層巢狀的 JSON | `RecursionError` traceback、結束碼 1（被當成「有呼叫被拒」） | 結束碼 2 | `a3a6a1f`（2026-11-21） |

已確認擋得住：收據換 `receipt_id` 重放（`REPLAYED_REQUEST`）、審批後改 content／command／old_string、自附 `content_sha256` 偽造、junction 指到工作區外（`OUTSIDE_ALLOWED_ROOT`）。

能力邊界（未改，README 已寫）：收據沒有簽章、單次使用不跨行程、驗證與執行之間的 TOCTOU、POSIX 上反斜線的語意差異、允許根目錄本身算在範圍內。

### verify_cloud_persistence_audit.py

| 編號 | 嚴重度 | 樣本 | 修前 | 修後 | 修復 |
| --- | --- | --- | --- | --- | --- |
| C-1 | 中 | MCP 設定 `"env":{"API_KEY":"ghp_…"},"env":{}`（帳號 JSON 同理） | 只看到最後的空 `env`，PASS、結束碼 0；憑證仍在檔案上 | 重複鍵回 2 | `022d23f`（2026-11-21） |
| C-2 | 中 | Claude Code `~/.claude.json` 的 `projects.<路徑>.mcpServers` 寫死憑證；VS Code `settings.json` 的 `mcp.servers` | 只看根層，結束碼 0（根層有其他 server）或 2 | 任何深度的 `mcpServers` 與 `mcp.servers` 都掃，結束碼 1 | `022d23f`（2026-11-21） |
| C-3 | 中 | `"command":"npx srv --token ghp_…"`、`args: ["--api-key", "…"]`、`--token=…`、`oauth.clientSecret`、`auth.value`、`cwd` 裡的金鑰 | 全部漏報 | 結束碼 1；`--token-file`、`--max-tokens`、`tokenUrl` 這類設定不報 | `022d23f`（2026-11-21） |
| C-8 | 中 | ai-inbox REVIEW.md 16.2（T-20261107-05）追加：`args: ["mcp-remote", "https://…", "--header", "X-Api-Key:<32 位 hex>"]`、`-H X-Auth-Token:…`、`--header=X-Api-Key:…`、`command` 字串裡的同樣寫法（`--api-key=<hex>` 已由 C-3 修掉） | `--header` 寫法 exit 0（headers／env 的敏感鍵名規則沒套到 args） | 名稱帶 token／key／secret／password／credential／cookie 的標頭值非佔位符就報，結束碼 1；`Accept: application/json`、`X-Api-Key:${API_KEY}` 不報 | `79b2788`（2026-11-21） |
| C-4 | 中 | 未列名鍵底下的 Google `AIza…`（Gemini／Vertex 金鑰，正是 LLMJacking 案例）、`gho_`／`ghs_`／`ghu_`／`ghr_`、`ASIA`、`glpat-`、`hf_`、`npm_`、`xoxs-`／`xapp-`、`sk_live_`、私鑰區塊；`Cookie` 標頭；`<ghp_…>` | 漏報（`<…>` 被當佔位符豁免） | 結束碼 1 | `022d23f`（2026-11-21） |
| C-5 | 低 | 角色 `" roles/owner"`、`roles/iam.serviceAccountTokenCreator`、`serviceAccountUser`、`workloadIdentityUser` | 不算高權限 | 標記 | `022d23f`（2026-11-21） |
| C-6 | 低 | 2 萬個同一秒建立的帳號 | 激增檢查 O(n²)，28.7 秒 | 線性，0.1 秒 | `022d23f`（2026-11-21） |
| C-7 | 低 | `--scan-dir` 裡的目錄連結：Windows junction 繞回自己、POSIX 符號連結目錄 | junction 迴圈路徑過長回 2（掃不完）；符號連結目錄不跟進、靜默漏掃 | 跟進並以實際路徑去重 | `022d23f`（2026-11-21） |

能力邊界（未改，README 已寫）：只比對固定檔名與 token 前綴、Run keys 只看 `Run`／`RunOnce`、自訂 IAM 角色不展開、值拆成多個參數或經 shell 變數組出來抓不到。

### audit_oauth_credentials.py

| 編號 | 嚴重度 | 樣本 | 修前 | 修後 | 修復 |
| --- | --- | --- | --- | --- | --- |
| O-1 | 高 | 被稽核的目錄在 repo 裡，該 repo 的 `.git/config` 設了 `core.fsmonitor=<指令>`（解壓來路不明的專案就會帶著 `.git/`） | `git_state`、`--repo` 的 `git ls-files` 執行了該指令（實測建出標記檔） | 所有 git 呼叫加 `-c core.fsmonitor=false`，不再執行 | `f322af7`（2026-11-21） |
| O-2 | 中 | `--repo` 指向不是 git repo 的目錄，或沒有 git | 只列 INFO、結束碼 0 | 結束碼 2 | `f322af7`（2026-11-21） |
| O-3 | 中 | `auth.json` 墊到 1 MB 以上，或檔案被鎖／沒有讀取權限 | 整檔跳過，ACL 授權給 Everyone、被 git 追蹤都不查；只列 INFO | 列 WARN，權限／ACL／git 照查 | `f322af7`（2026-11-21） |
| O-4 | 低 | `"password"`、`"private_key"`、`"Authorization": "Bearer …"`；JSON 值換到下一行 | 漏報 | 列入欄位類別；只有引號字串可換行，`.env` 的空值不會吃掉下一行 | `f322af7`（2026-11-21） |
| O-5 | 低 | `--repo` 裡被追蹤、含明文金鑰的 `.env`、`.env.production` | 不看 | ERROR；`.env.example` 等範本與沒有值的 `.env` 不報 | `f322af7`（2026-11-21） |

能力邊界（未改，README 已寫）：JSON `\u` 跳脫的鍵名、只授權給特定其他帳號的 ACL、`icacls` 讀不到 ACL 維持 INFO、無 BOM 的非 ASCII UTF-16。

### screen_privacy.py

| 編號 | 嚴重度 | 樣本 | 修前 | 修後 | 修復 |
| --- | --- | --- | --- | --- | --- |
| S-1 | 高 | `--ocr-file` 是 UTF-16（PowerShell 5 的 `>`、`Out-File` 預設），內含 GitHub token | `action: pass`，並在 `redacted:` 之後印出含金鑰的全文；cp950 檔的中文關鍵字也比對不到而 pass | 依 BOM／NUL 比例解 UTF-8／16／32 → `drop_image`；都解不開也 `drop_image`、不印文字 | `cd94185`（2026-11-21） |
| S-2 | 中 | 長金鑰被 OCR 折成兩行（窄視窗、終端換行），例如 `sk-ant-api03-…` 在第 10、20、30 字元處換行 | `pass` | 有固定前綴的金鑰接回後再比對 → `drop_image`；一般文字不接行 | `cd94185`（2026-11-21） |
| S-3 | 中 | 標題：全形 `Ｉｎｃｏｇｎｉｔｏ`、`Online Banking`、兩個空白、全形空白、半形片假名 `ｶﾙﾃ`、`P`＋U+0301；OCR：全形 AWS 金鑰、`Ａ123456789`、零寬字元夾在金鑰中、NBSP 分隔的卡號 | 標題 `ok`、OCR `pass` | 比對前去不可見字元＋NFKC＋收斂空白，標題另比去附加符號版本 → `blocked`／`drop_image` | `cd94185`（2026-11-21） |
| S-4 | 低 | Linux／macOS 行程名稱 `keepassxc`、`1password`、`KeePassXC.app` | `ok` | 同時比對有、無 `.exe` → `blocked` | `cd94185`（2026-11-21） |
| S-5 | 中 | `id_ed25519 - Notepad`、`server.ppk`、`vault.kdbx`、`.envrc`、`.netrc`、`.pgpass`、`.git-credentials`、`.npmrc`、`.pypirc`、`auth.json`、`credentials - Notepad`（`~/.aws/credentials`）；終端機標題 `nano .env` | `ok` | `blocked`；`.key` 刻意不收（Keynote） | `cd94185`（2026-11-21） |
| S-6 | 低 | `-----BEGIN  RSA  PRIVATE  KEY-----`（OCR 多出空白） | `pass` | `drop_image` | `cd94185`（2026-11-21） |

能力邊界（未改，README、規範已寫）：金鑰中間被插入空白、卡號用兩個以上空白或句點分隔、西里爾字母等異體字、第二層 UIA 未實作、結束碼不反映判斷結果。效能：S-1～S-6 讓既有 ReDoS 樣本變慢約一倍（機器忙碌時 1 秒門檻測試會偶發紅燈），已補純 ASCII 快速路徑、同一段文字只算一次、只在有換行折斷時才接行，40 KB 樣本降到 0.03～0.06 秒（修前約 0.04～0.07 秒）；修復 `57b4bf1`（2026-11-21）。

### Mutation 與誤報

- Mutation：57 個突變（含 C-8 的 3 個、效能修正後 OCR 路徑的 4 個）（每個修正至少一個：把條件改成恆假、刪掉新增的樣式或鍵名、還原舊的解碼與正規化）全部讓對應測試模組轉紅。第一輪有 2 個存活（無 BOM UTF-16 只拿掉 NUL 也能讀 ASCII；標題的去附加符號版本已涵蓋全形），補了 `test_utf16_without_bom_keeps_chinese_text`、`test_fullwidth_titles_for_self_and_nocap` 後轉紅。
- 本機真實無害資料（只看計數，不輸出內容）：目前桌面視窗、`~/.claude/skills` 下 459 個檔名當標題、同批檔案內文當 OCR、Run keys、Startup 資料夾、`~/.claude.json` 的 MCP 設定、預設的 OAuth 稽核。修前修後結果相同：視窗分類不變、檔名標題只有 1 個 `blocked`（本來就有）、內文 `drop_image` 17 個（本來就有，都是文件裡的範例憑證與身分證樣式）、Run keys／Startup／`~/.claude.json` 都 PASS、OAuth 稽核 0 ERROR／3 WARN。
