# AGENTS.md

本 repo 是一組給 AI agent 用的本機安全檢查工具（只用 Python 標準函式庫）。給所有 AI 編碼 agent 與人類維護者看。專案指令檔只放本檔，不建 `CLAUDE.md`、`GEMINI.md`。

## 鐵律

1. **安全檢查無法判斷就判失敗。** 讀不到、解析失敗、輸入是空的、欄位型別不對、有檔案沒掃到，一律不得回 0／PASS。寧可誤擋，不可誤放。
2. **每個反例都要變成回歸測試。** 發現漏報或誤報，先寫會紅的測試，再修判斷邏輯。
3. **改判斷邏輯要做 mutation 確認有測試會紅。** 把判斷條件反轉或刪掉一條規則，至少一個測試要失敗；沒有紅的測試就是沒在保護那條邏輯，補測試。
4. **不輸出機密內容。** 錯誤訊息與報告不回顯 token、金鑰、原始輸入片段。
5. **只用標準函式庫。** 不加第三方相依；跨平台（Windows／Linux）都要能跑。
6. **工具說明要照實寫能力邊界。** 新增或修改偵測行為，同步更新 README 的「能力邊界」與 ROADMAP。
7. **公開 repo：不放機密、不寫真實的家目錄帳號**；測試用的假金鑰一律用字串拼接產生。
8. 結束碼語意：0 通過、1 命中問題、2 輸入錯誤或無法判斷。新工具照此，除非 README 工具表明文註記例外。

## 開發流程

```
寫會紅的測試 ─► 修改 ─► 測試轉綠（3.11 與 3.14） ─► mutation 確認 ─► 同步文件 ─► commit
```

- 測試指令：`python -m unittest discover -s tests`。**不設 `PYTHONUTF8`**，要抓得到只在 Windows 預設編碼（cp950／cp1252）才發生的錯誤。
- 本機兩個版本都要全過：`py -V:Astral/CPython3.11.15 -m unittest discover -s tests` 與 `python -m unittest discover -s tests`（3.14）。CI 跑 ubuntu-latest 與 windows-latest 的 Python 3.11。
- 測試與 `git commit` 之間用 `&&` 串接，不用 `;`：測試紅燈就不得提交。
- 不改寫已提交的歷史（本 repo 保留 ai-inbox 的原始歷史）。
- GitHub Actions 一律釘 commit SHA，`permissions: contents: read`；唯一例外是 CodeQL 上傳結果需要的 `security-events: write`。
- 每支工具的 `--help` 在 cp950 下要能輸出 UTF-8、結束碼 0、無副作用（`tests/test_cli_help_encoding.py`）。
- 若有 `REVIEW.md`，修復其中項目後回註修復 commit 與日期。

## 目錄結構

```
tools/    五支檢查工具（各自獨立，單檔可執行）
tests/    對應的 unittest；test_cli_help_encoding.py 檢查所有工具的 --help
docs/     multimodal-screen-privacy-spec.md（screen_privacy.py 的規範，以程式為準）
.github/workflows/ci.yml       測試（ubuntu／windows，Python 3.11）
.github/workflows/codeql.yml   CodeQL（python、actions）
.github/dependabot.yml         只追 GitHub Actions；freshness、multi-commit 的 waiver 與理由也寫在這裡
README.md   用途、工具表、能力邊界
ROADMAP.md  後續工作與刻意不做的事（單一真相源）
```
