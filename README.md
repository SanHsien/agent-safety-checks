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

結束碼由 `tests/test_cli_exit_codes.py` 的獨立行程測試守住通過、命中、裸執行、缺參數與錯誤路徑；`--help` 另由 `tests/test_cli_help_encoding.py` 檢查。

| 指令 | 用途 | 結束碼 |
|------|------|--------|
| `python tools/verify_agent_skill_pack_safety.py --pack <目錄>` | 採納前靜態掃描技能包（可重複 `--pack`；另有 `--strict`、`--json`、`--max-bytes`、`--ack-unscanned`；`--config`／`--self-test` 只檢查自述宣告，不能當採納依據） | 0 通過；1 有 FAIL（`--strict` 時 REVIEW 也算）；2 輸入錯誤或無法掃描（裸執行、目錄不存在或為空、有未掃描檔且未確認） |
| `python tools/verify_tool_call_firewall.py --verify-calls <json>` / `--analyze-trace <json>` | 驗證工具呼叫的單次審批收據與請求雜湊；分析 Agent trace 的 span 去重耗時與 token | 0 全部通過；1 有呼叫被拒；2 沒給參數、檔案不存在或無法讀取，或 JSON／schema 無效 |
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

2026-11-20 依實際審查五個第三方 repo 的結果補的規則。每一條都是句型或指令樣式比對，下表右欄的寫法都抓不到：

| 類別（嚴重度） | 抓得到 | 抓不到 |
| --- | --- | --- |
| `DEFENSE-OFF`（可執行位置 FAIL；說明文字 REVIEW） | `xattr -d com.apple.quarantine`、`xattr -c`／`-cr`；`spctl --master-disable`；`csrutil disable`；`Set-MpPreference -Disable…`（含 `-DRTM`、`-DIOAVP` 這類參數別名）、`Add-MpPreference -Exclusion…`；`Unblock-File`、刪除 `Zone.Identifier`；用 `reg`／`Set-ItemProperty` 把 `EnableLUA` 等設 0 或把 Defender 的 `Disable…` 設 1；`netsh … state off`、`Set-NetFirewallProfile -Enabled False`。說明文字叫使用者在 SmartScreen 選「仍要執行」、在 Gatekeeper 選「仍要打開」、關閉防毒／UAC／防火牆。Markdown 說明文字、行內程式碼、程式碼區塊、frontmatter 與 JSON 的說明字串裡，接在「Then:」「Run」「先執行」之後（不在行首）的上述移除防護指令也列 REVIEW：指令黏在前文（`請執行xattr`、`Then:xattr`、全形冒號）、包在粗體或連結文字裡（含 `[run xattr -cr](…)` 旗標黏著網址）、句尾帶標點、前面有撇號（`Don't`）、或在同一段落裡換行斷開都算；連「請勿執行」的警告句也會列（分不出是指示還是警告，交人工判斷） | 其他關閉方式（群組原則、`sc stop`、`launchctl`、第三方防毒自己的指令、Linux 的 SELinux／AppArmor）；旗標或鍵名存在變數裡；圖形介面操作的其他說法；只寫「允許此應用程式」這類沒提到防護名稱的句子；指令名之後超過 64 個 token 才出現的參數；被空白行隔開的兩段；同一段落已有一行列了 `DEFENSE-OFF` 時，段落裡其他跨行斷開的指令不另外列 |
| `AGENT-STEER`：搶占（REVIEW） | 「prefer／always use X over／instead of／rather than 內建或其他工具」「read this skill by default」「takes precedence over other skills」「never use the built-in …」與對應的中文句型，出現在 frontmatter、內文、JSON 字串或程式字串都算 | 換句話說的寫法（例如只寫「所有網頁工作都交給我」）；中英以外的語言；只限制自己用哪些工具的句子（例如 `do not use other tools`）刻意不列 |
| `AGENT-STEER`：不必請求授權（REVIEW） | 「do not／never／no need to … ask／request／wait for … permission／authorization／approval／confirmation」「constitutes／counts as … authorization」「replaces … user approval」與中文「不要再向使用者請求授權」「視為已授權」 | 否定詞和動詞隔了一個句子以上；用「直接執行」「全自動」這類不提授權的說法；`never proceed without asking` 這種方向相反的句子刻意不列。分級為 REVIEW 而不是 FAIL，因為句型分不出「叫你不要問」與「引述一條不該照做的規則」，而且說明文字在本工具一律是 REVIEW |
| `AGENT-STEER`：讀遠端網址並照做（REVIEW） | 「read／fetch／open `https://…` and follow …」「follow the instructions at `https://…`」「讀取 `https://…` 並照著做」 | 網址存在變數或另一個檔案；只給網址沒有「照做」字眼；給人看的安裝文件也會命中（無法分辨讀者是人還是 agent） |
| `AGENT-STEER`：指引在執行期才印出（REVIEW，只看 `SKILL.md`、`AGENTS.md` 與 `skills/`、`commands/`、`agents/`、`rules/`、`prompts/` 下的說明檔） | 「run `<指令>` to load／get／print … instructions／guidance」「follow whatever it prints」「執行 … 依印出的指引」 | 其他位置的檔案；沒有提到 instructions／guidance 等字眼的寫法；印出的內容本身（那是已安裝的程式，不在技能目錄裡） |
| `CRED-ACCESS`：Cookie 注入式登入說明（REVIEW） | 「copy／export／extract cookies … from browser／DevTools」「inject cookies into … session／context」「把 Cookie 標頭複製進 …」 | 程式直接呼叫 `add_cookies`／`setCookie` 之類的 API；不出現 cookie 字眼的 session token 搬移 |
| `REMOTE-EXEC`：clone 後執行其中的安裝程式（REVIEW） | 同一份腳本或同一個程式碼區塊裡，`git clone` 之後執行名稱是 `install*`／`setup*`／`bootstrap*` 的腳本，而且路徑含 clone 的目的地（變數或目錄名）或先 `cd` 進去；中間 `git checkout`／`reset`／`switch` 到 commit 雜湊就不列。`--branch <標籤>` 不算固定 | clone 與執行分在兩個檔案；`make install`、`npm install`、`pip install .` 這類不是腳本檔名的安裝；`git pull` 更新後再執行；`gh repo clone`、下載壓縮檔再解開。技能包的 README 教人 clone 它自己再跑安裝程式也會命中，這時要確認安裝腳本在掃描範圍內 |
| `PERSISTENCE`：改寫 shell 啟動檔（REVIEW） | 用 `>`／`>>`、`tee`、`sed -i`、`Add-Content`、`Out-File`、`Set-Content` 寫入 `.bashrc`、`.zshrc`、`.profile`、`config.fish`、`$PROFILE` 等，含先把路徑存進變數再寫（`RC="$HOME/.zshrc"`） | 程式語言的檔案 API（Python `open(…, "a")`、Node `fs.appendFile`）；其他持久化位置（crontab、LaunchAgents、Windows 排程與 Run keys、systemd）；變數經過兩層以上轉手 |

同一批審查修掉的誤判（都只降為 REVIEW，不是不報）：

| 情況 | 現在的判定 | 仍然 FAIL 的相似寫法 |
| --- | --- | --- |
| 別的工具自己的 `--yolo` 模式名，跟在斜線指令後面（`/autopilot target --yolo`） | REVIEW | 同一道指令出現任何 agent CLI 名稱（`codex`、`gemini`、`claude`…）、不是斜線指令開頭、包在 `bash -c '…'` 裡、其他略過權限旗標 |
| 說明文字同時提到「user data」與「cookies」（`user_data_dir` 參數說明），兩者之間沒有任何路徑分隔 | REVIEW | 中間有斜線或反斜線的路徑、`os.path.join(…, "User Data", …, "Cookies")`、`Path / "User Data" / "Cookies"`、`cd …/User Data/Default && cp Cookies` |
| 下載指令的對象只有 loopback 位址（`localhost`、`127.x.x.x`、`[::1]`）再接管線給直譯器 | REVIEW | 主機名只是以 `localhost` 開頭、網址帶 `@`、多個網址其中一個不是 loopback、帶 `-L`／`-K`／`-x` 或任何白名單以外的參數、前面有環境變數或 `sudo`、網址是變數 |

刻意維持 FAIL 的情況：遠端內容經 `xargs` 代入 `sh -c '…'` 的指令字串（例如把抓回的網址逐一 `curl -X PURGE`）。它不是下載後整份執行，但遠端內容進了 shell 的程式碼位置，靜態無法證明安全。

其餘邊界：

- 執行期才組出來的內容：變數間接（最多 REVIEW）、字串拼接出的旗標、從檔案或環境變數讀進來的參數。
- 編碼與混淆：base64、十六進位、壓縮檔、被壓縮混淆的 JavaScript；只有 PowerShell 編碼指令與「解碼後接管線」會標 `OBFUSCATED`。
- 不經管線的遠端執行：`npx`／`uvx`／`pipx run`、`pip install git+https://…`、`mshta`、`certutil -urlcache`、程式內用 HTTP 函式庫下載再執行。
- 二進位與壓縮檔（`.zip`、`.dxt`、執行檔、圖片）只列為未掃描；技能包以外的東西（相依套件、執行期下載的程式、遠端 MCP 伺服器行為）不在範圍。
- 不靠危險旗標的攻擊：上表句型以外的提示詞注入、合法指令濫用、規則表沒列的憑證路徑、資料外傳。
- 已知仍會誤判：`curl <網址> | python3 -m json.tool` 這類只把回應排版的管線照樣 FAIL；測試檔裡斷言「參數不含某旗標」的那一行照樣 FAIL（程式檔裡的字串分不出是斷言還是指令）。
- 旗標清單會過期；YAML frontmatter 只認區塊式寫法（標準庫沒有 YAML 解析器）。
- 宣告模式（`--config`、`--self-test`）檢查的是填寫者自述，無法驗證真偽。
- 細節與來源見 [ai-inbox 的技能包審計文件](https://github.com/SanHsien/ai-inbox/blob/main/docs/claude-code-domain-skill-packs-and-mcp-audit.md)。

### verify_tool_call_firewall.py
- 審批收據只是請求內容的 SHA-256 雜湊，**沒有簽章**：任何能呼叫 `issue_approval_receipt` 的人都能自己造收據。它防的是「審批後內容被改」與「同一張收據重放」，不防偽造審批。
- 單次使用只在單次執行（單一行程、單一批次檔）內記錄，不跨行程持久化。
- 只認內建的五種工具名稱與各自的欄位白名單；路徑只做邏輯檢查，不確認實體檔案系統上的符號連結。
- trace 分析是算術去重，不判斷 span 內容是否可信。
- 檔案不存在、路徑不是檔案或無法讀取時回 2（無法判斷），不算規則命中。

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

這些工具原本在 [SanHsien/ai-inbox](https://github.com/SanHsien/ai-inbox) 內開發，後來用 git-filter-repo 切出獨立 repo，**保留原本的 git 歷史**（commit 訊息裡的 `T-2026…` 編號是 ai-inbox 當時的任務編號）。文件裡指向仍留在 ai-inbox 的檔案，一律是 `https://github.com/SanHsien/ai-inbox/blob/main/...` 絕對網址。

後續工作與刻意不做的事見 [ROADMAP.md](ROADMAP.md)；開發規則見 [AGENTS.md](AGENTS.md)。

## 授權

MIT，見 [LICENSE](LICENSE)。
