# ROADMAP

本 repo 後續工作的**單一真相源**。要做什麼、刻意不做什麼，都記在這裡；其他文件不另列待辦。

## 待做

- [ ] 首次推上 GitHub 後確認 CI（ubuntu／windows，Python 3.11）全綠。
- [ ] 各工具 docstring 與測試檔殘留 ai-inbox 時代的任務編號（`T-2026…`），之後逐步改成指向本 repo 的 issue 或移除（不改判斷邏輯）。
- [ ] 為每支工具補「裸執行／錯誤路徑結束碼」的 CLI 契約測試（目前 README 工具表的結束碼是人工實跑核對，不是由測試守住）。

## 刻意不做

已知的限制，經評估後不修，原因附在後面。要改變決定，先改這一節再動手。

| 工具 | 限制 | 為什麼不修 |
|------|------|-----------|
| verify_tool_call_firewall | 審批收據沒有簽章，只是請求雜湊，可被自行簽發 | 簽章需要金鑰管理，超出「只用標準函式庫的本機檢查」範圍；定位是防事後竄改與重放，不防偽造審批 |
| verify_tool_call_firewall | 單次使用狀態不跨行程持久化 | 持久化要面對鎖與狀態檔被竄改，風險比收益大 |
| verify_agent_skill_pack_safety | 抓不到變數間接、字串拼接、base64 等執行期才組出的內容 | 靜態啟發式的本質上限；只列 REVIEW，要人判斷。要抓得到就得執行內容，與「不執行」的原則衝突 |
| verify_agent_skill_pack_safety | 不掃二進位、壓縮檔、相依套件 | 只列為未掃描並要求逐檔確認；解開或下載會違反不執行原則 |
| verify_agent_skill_pack_safety | 標準庫沒有 YAML 解析器，flow 樣式 frontmatter 不認 | 不引入第三方相依 |
| verify_cloud_persistence_audit | `--scan-dir` 只比對固定檔名，不自動發現啟動資料夾 | 自動發現會讀使用者全域位置，擴大副作用面；呼叫端明確指定目錄 |
| audit_oauth_credentials | 無 BOM 的非 ASCII UTF-16、無 BOM 的 UTF-32 會漏報 | 無 BOM 時無法可靠判斷編碼；PowerShell 5 的輸出有 BOM，不屬此情況 |
| screen_privacy | 第二層（Windows UIA 無障礙樹）未實作 | 需要 COM，無法跨平台、純標準庫實作與測試 |
| screen_privacy | 結束碼不反映判斷結果（blocked 也回 0） | 沿用既有呼叫端的契約，判斷結果在 stdout；改動會破壞既有整合，需要時另開新旗標而不是改預設 |
