# 路線圖

> 本 repo 後續工作的單一真相源。做完一項，就在同一個 commit 刪掉那一列；新工作只加在這裡。
> 現況段是 2026-11-15 查的快照，開工前先重查。

## 現況
本機 AI agent 安全檢查工具集（五支工具，只用 Python 標準函式庫），2026-11-14 自 ai-inbox 抽出成獨立的公開 repo（`gh repo view`），MIT 授權。`c44b226` 的 CI（ubuntu／windows，Python 3.11）為 success（`gh run list`，2026-11-15）。2026-11-15 依艦隊標準補上 Dependabot（只追 GitHub Actions）與 CodeQL（python、actions）；沒有套件 manifest，依賴新鮮度與歷史壓縮以 `.github/dependabot.yml` 的 waiver 註明理由。

## 近期：可以直接動手

| 項目 | 為什麼 | 驗收方式 | 建議執行者 | 證據 |
| --- | --- | --- | --- | --- |
| 改掉 ai-inbox 時代的任務編號 | 2 個檔案的 docstring 仍寫 `T-2026…`（抽出前的 ai-inbox 任務編號），在本 repo 查不到 | 改成指向本 repo 的 issue 或移除，不改判斷邏輯；`python -m unittest discover -s tests` 全過 | Claude Haiku | `tools/verify_agent_skill_pack_safety.py:3`；`tests/test_verify_agent_skill_pack_safety.py:2` |
| 每支工具補裸執行／錯誤路徑結束碼的 CLI 契約測試 | README 工具表的結束碼是人工實跑核對，沒有測試守住（AGENTS.md 鐵律 8：0 通過、1 命中、2 輸入錯誤或無法判斷） | 每支工具至少一個「裸執行」與一個「無法判斷」案例，先紅後綠；mutation 反轉結束碼時測試會紅 | Claude Sonnet | `README.md` 工具表；`AGENTS.md` 鐵律 8 |

## 中期：等條件成立再做

| 項目 | 觸發條件 | 驗收方式 | 建議執行者 | 證據 |
| --- | --- | --- | --- | --- |

## 刻意不做

| 不做什麼 | 理由 | 什麼情況下重新考慮 |
| --- | --- | --- |
| `verify_tool_call_firewall`：審批收據沒有簽章，只是請求雜湊，可被自行簽發 | 簽章需要金鑰管理，超出「只用標準函式庫的本機檢查」範圍；定位是防事後竄改與重放，不防偽造審批 | 要改變決定，先改這一列再動手 |
| `verify_tool_call_firewall`：單次使用狀態不跨行程持久化 | 持久化要面對鎖與狀態檔被竄改，風險比收益大 | 要改變決定，先改這一列再動手 |
| `verify_agent_skill_pack_safety`：抓不到變數間接、字串拼接、base64 等執行期才組出的內容 | 靜態啟發式的本質上限；只列 REVIEW，要人判斷。要抓得到就得執行內容，與「不執行」的原則衝突 | 要改變決定，先改這一列再動手 |
| `verify_agent_skill_pack_safety`：不掃二進位、壓縮檔、相依套件 | 只列為未掃描並要求逐檔確認；解開或下載會違反不執行原則 | 要改變決定，先改這一列再動手 |
| `verify_agent_skill_pack_safety`：標準庫沒有 YAML 解析器，flow 樣式 frontmatter 不認 | 不引入第三方相依 | 要改變決定，先改這一列再動手 |
| `verify_cloud_persistence_audit`：`--scan-dir` 只比對固定檔名，不自動發現啟動資料夾 | 自動發現會讀使用者全域位置，擴大副作用面；呼叫端明確指定目錄 | 要改變決定，先改這一列再動手 |
| `audit_oauth_credentials`：無 BOM 的非 ASCII UTF-16、無 BOM 的 UTF-32 會漏報 | 無 BOM 時無法可靠判斷編碼；PowerShell 5 的輸出有 BOM，不屬此情況 | 要改變決定，先改這一列再動手 |
| `screen_privacy`：第二層（Windows UIA 無障礙樹）未實作 | 需要 COM，無法跨平台、純標準庫實作與測試 | 要改變決定，先改這一列再動手 |
| `screen_privacy`：結束碼不反映判斷結果（blocked 也回 0） | 沿用既有呼叫端的契約，判斷結果在 stdout；改動會破壞既有整合，需要時另開新旗標而不是改預設 | 要改變決定，先改這一列再動手 |

## 維護方式
依 `AGENTS.md` 的開發流程：先寫會紅的測試、修改、3.11 與 3.14 都轉綠、mutation 確認、同步 README 與本檔，再提交。Dependabot 只開 Actions 的 PR；合併前確認 SHA 對應宣稱的版本。
