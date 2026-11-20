#!/usr/bin/env python3
"""
verify_agent_skill_pack_safety.py — 第三方 Claude Code / Agent Skill 與 MCP 工具鏈採納前安全與決定性靜態審計器

這是「靜態啟發式掃描」，不執行、不下載任何技能包內容。通過不代表安全，仍需人工審查。

用法：
  python tools/verify_agent_skill_pack_safety.py --pack <技能包目錄> [--pack <另一個目錄> ...]
      主要用法：實際讀取目錄內的檔案並掃描。
  python tools/verify_agent_skill_pack_safety.py --config <宣告.json>
      補充用法：檢查「填寫者自述」的 JSON 宣告（SKILLPACK-001 ~ 004）。宣告模式不讀任何
      第三方檔案，結果不能當作採納依據。
  python tools/verify_agent_skill_pack_safety.py --self-test
      只對內建的宣告範例做自檢（回 0 或 1），同樣不能當作採納依據。
  不帶 --pack、--config、--self-test 的裸執行什麼都沒檢查，會提示改用 --pack 並回 2。

目錄掃描的偵測類別（細節、來源與抓不到的東西見 https://github.com/SanHsien/ai-inbox/blob/main/docs/claude-code-domain-skill-packs-and-mcp-audit.md）：
  BYPASS        免審批／破沙盒旗標與設定值
  REMOTE-EXEC   遠端內容接管線、替換或下載後直接執行
  OBFUSCATED    編碼過、無法靜態判讀的指令
  DYNAMIC-EXEC  執行非字面內容（iex $c、eval "$s"、bash -c "$s"、eval(code)）；只列 REVIEW，不判 FAIL
  CRED-ACCESS   讀取瀏覽器 Cookie／登入資料庫或憑證檔
  INSTALL-EXEC  安裝時自動執行的腳本（npm lifecycle 等）
  AUTO-HOOK     審批之外自動執行的 hook／技能內嵌指令（列出內容，需人工審查）
  MCP-SERVER    MCP 伺服器啟動指令或遠端位址（列出內容，需人工審查）
  DEFENSE-OFF   移除或關閉系統防護（macOS 隔離屬性／Gatekeeper／SIP、Windows Defender／UAC／防火牆／
                下載標記）；說明文字叫使用者在 SmartScreen、Gatekeeper 點「仍要執行」只列 REVIEW
  AGENT-STEER   寫給 agent 的指示：搶占其他工具、不要再請求授權、去讀遠端網址並照做、
                指引在執行期才由程式印出；只列 REVIEW，不判 FAIL
  PERSISTENCE   改寫 shell／PowerShell 啟動檔；只列 REVIEW，不判 FAIL

嚴重度：
  FAIL    在可執行的位置（腳本、設定、程式碼區塊）發現已知危險樣式。
  REVIEW  工具無法替人判斷，列出來要人看：hook 指令、MCP 指令、說明文字裡提到的旗標等。
          預設不影響結束碼；加 --strict 時視同 FAIL。

結束碼：
  0  通過：掃描完整，沒有 FAIL。REVIEW 項目仍須人工審查。
  1  發現問題：至少一項 FAIL（或 --strict 下有 REVIEW）；宣告模式則是違反 SKILLPACK 規則。
  2  輸入錯誤或無法掃描：沒有指定檢查對象、目錄或檔案不存在、讀不到、是空的、JSON 壞掉、
     宣告結構不合法，或有檔案未掃描（二進位、超過大小上限、符號連結）且沒有用
     --ack-unscanned 逐檔確認。
  同時有 FAIL 和未掃描檔時回 1（已經確定有問題）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
MAX_NESTING = 3

FAIL = "FAIL"
REVIEW = "REVIEW"

CAT_BYPASS = "BYPASS"
CAT_REMOTE = "REMOTE-EXEC"
CAT_OBFUSCATED = "OBFUSCATED"
CAT_DYNAMIC = "DYNAMIC-EXEC"
CAT_CRED = "CRED-ACCESS"
CAT_INSTALL = "INSTALL-EXEC"
CAT_HOOK = "AUTO-HOOK"
CAT_MCP = "MCP-SERVER"
CAT_DEFENSE = "DEFENSE-OFF"
CAT_STEER = "AGENT-STEER"
CAT_PERSIST = "PERSISTENCE"


def _ensure_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 規則表。旗標字串拆開組合，避免本檔自己被關鍵字型的守門 hook 擋下。
# 每一項的官方來源（或「未查證」）列在 https://github.com/SanHsien/ai-inbox/blob/main/docs/claude-code-domain-skill-packs-and-mcp-audit.md。
# ---------------------------------------------------------------------------

_D = "--danger" + "ously-"
_SKIP = "skip-" + "permissions"
_BYPASS_MODE = "bypass" + "permissions"  # 比對一律轉小寫
_FULL_ACCESS = "danger-" + "full-access"

# 單一旗標，出現就算。
FAIL_FLAGS: dict[str, str] = {
    _D + _SKIP: "Claude Code：略過所有權限提示",
    "--allow-" + _D[2:] + _SKIP: "Claude Code：把略過權限模式加進可切換的模式",
    _D + "bypass-approvals-and-sandbox": "Codex：不審批也不用沙盒",
    "--yo" + "lo": "Codex：上一項的別名；Gemini CLI 等也用同名旗標自動核准",
    _D + "bypass-hook-trust": "Codex：hook 不需要事先信任就執行",
    "--full-" + "auto": "未查證的自動核准旗標",
}

# 這些旗標名稱太普通，別的工具也拿來當自己的模式名。跟在斜線指令（/autopilot 之類）後面、
# 同一道指令裡又沒有任何 agent CLI 時降為 REVIEW；其餘情況照樣 FAIL。
CONTEXT_FLAGS = {"--yo" + "lo"}
AGENT_CLIS = {
    "codex", "gemini", "qwen", "claude", "opencode", "aider", "goose", "amp", "droid", "copilot",
    "cursor-agent", "hermes", "crush", "cline", "kiro", "agent",
}
_SLASH_COMMAND_RE = re.compile(r"^/[A-Za-z][\w:.-]*$")

# 會降低審批強度、但不是完全關掉的旗標。
REVIEW_FLAGS: dict[str, str] = {
    "--approve-for-me": "Codex：改由自動審查核准",
    "--not-so-" + "yolo": "Codex：上一項的別名",
}

_MODE_KEYS = ("--permission-mode", "permission-mode", "permissionmode", "permission_mode", "defaultmode")
_SANDBOX_KEYS = ("--sandbox", "-s", "sandbox", "sandbox_mode")
_APPROVAL_KEYS = ("--ask-for-approval", "-a", "approval_policy")

# 「旗標或設定鍵」加「值」。
FAIL_PAIRS: dict[tuple[str, str], str] = {}
for _k in _MODE_KEYS:
    FAIL_PAIRS[(_k, _BYPASS_MODE)] = "Claude Code：權限模式設為略過所有檢查"
for _k in _SANDBOX_KEYS:
    FAIL_PAIRS[(_k, _FULL_ACCESS)] = "Codex：沙盒設為完全存取"
for _k in _APPROVAL_KEYS:
    FAIL_PAIRS[(_k, "never")] = "Codex：審批設為從不詢問"
for _k in ("skipdangerousmodepermissionprompt", "enableallprojectmcpservers", "allowdangerouslyskippermissions"):
    FAIL_PAIRS[(_k, "true")] = "設定值：關掉確認對話框或自動核准"

REVIEW_PAIRS: dict[tuple[str, str], str] = {}
for _k in _MODE_KEYS:
    for _v in ("acceptedits", "auto"):
        REVIEW_PAIRS[(_k, _v)] = "Claude Code：權限模式會自動核准部分動作"

# 單獨出現的值（前面不是已知的鍵，例如先存進變數）。無法判斷用途，列為 REVIEW。
LONE_VALUES = {_BYPASS_MODE, _FULL_ACCESS}

DOWNLOADERS = {"curl", "wget", "fetch", "aria2c", "irm", "iwr", "invoke-webrequest", "invoke-restmethod"}
DECODERS = {"base64", "xxd", "openssl", "certutil"}
EXECUTORS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh",
    "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua",
    "pwsh", "powershell", "cmd", "osascript",
    "iex", "invoke-expression", "[scriptblock]::create", "source", ".", "eval",
}
_PS_EVAL = {"iex", "invoke-expression"}
WRAPPERS = {
    "sudo", "doas", "env", "command", "exec", "nohup", "time", "builtin", "call",
    "start", "start-process", "saps", "stdbuf", "nice", "xargs",
}
_SHELL_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "(", "$(", "&"}

_DL_METHOD_RE = re.compile(r"downloadstring|downloadfile|net\.webclient|start-bitstransfer")
_SUBST_DL_RE = re.compile(
    r"(?:\$\(|`|<\(|\(|\{)\s*(?:sudo\s+)?(?:curl|wget|irm|iwr|invoke-webrequest|invoke-restmethod)\b"
    r"|downloadstring|downloadfile|net\.webclient"
)
_CODE_EXEC_RE = re.compile(r"\b(?:exec|execsync|system|runinnewcontext|runinthiscontext)\s*\(|\beval\b|new\s+function\b")
_CODE_FETCH_RE = re.compile(r"\b(?:urlopen|urlretrieve|fetch|axios)\s*\(|\brequests\.(?:get|post)\s*\(|\bhttps?\.get\s*\(")

_S = r"[/,\s+]+"  # 路徑片段之間可能出現的分隔：斜線、逗號（os.path.join）、空白、加號
CRED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            rf"(?:user data|google{_S}chrome|google-chrome|microsoft{_S}edge|microsoft-edge|bravesoftware"
            rf"|brave-browser|/chromium/|opera software)(?P<gap>.{{0,200}}?)(?P<sep>{_S})"
            r"(?:cookies|login data|web data|local state)\b"
        ),
        "瀏覽器設定檔內的 Cookie／登入資料庫",
    ),
    (re.compile(r"\b(?:cookies\.sqlite|key4\.db|cookies\.binarycookies)\b"), "瀏覽器 Cookie／金鑰資料庫檔名"),
    (re.compile(r"--cookies-from-browser\b|\bbrowser_cookie3\b|\bpycookiecheat\b|\brookiepy\b|cryptunprotectdata"), "讀取或解密瀏覽器 Cookie 的工具"),
    (re.compile(rf"\.aws{_S}(?:credentials\b|sso{_S}cache\b)"), "AWS 憑證檔"),
    (re.compile(rf"\.ssh{_S}(?:id_[a-z0-9]+|identity)\b(?!\.pub)"), "SSH 私鑰"),
    (re.compile(r"(?<![\w.])[._]netrc\b|\.git-credentials\b"), ".netrc／git 憑證檔"),
    (re.compile(rf"\.docker{_S}config\.json|\.kube{_S}config\b"), "Docker／Kubernetes 憑證設定"),
    (re.compile(rf"gcloud{_S}(?:credentials\.db|access_tokens\.db|application_default_credentials\.json)"), "gcloud 憑證檔"),
    (re.compile(rf"\.config{_S}gh{_S}hosts\.ya?ml"), "GitHub CLI 憑證檔"),
    (re.compile(rf"\.claude{_S}\.credentials\.json|\.codex{_S}auth\.json"), "Agent CLI 登入憑證"),
    (re.compile(r"\bfind-(?:generic|internet)-password\b|login\.keychain"), "macOS 鑰匙圈"),
]

NPM_INSTALL_FAIL = ("preinstall", "install", "postinstall")
NPM_INSTALL_REVIEW = ("prepublish", "preprepare", "prepare", "postprepare")

JSON_EXEC_KEYS = {
    "command", "args", "cmd", "run", "exec", "script", "scripts", "shell", "entrypoint",
    "apikeyhelper", "awsauthrefresh", "awscredentialexport", "otelheadershelper", "statusline", "filesuggestion",
}
HOOK_TYPES_OTHER = {"http", "prompt", "agent", "mcp_tool"}

MARKDOWN_EXT = {".md", ".mdx", ".markdown", ".txt", ".rst"}
PROSE_NAMES = {"license", "licence", "notice", "copying", "authors", "changelog", "readme"}
HASH_COMMENT_EXT = {
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".psd1", ".py", ".pyw", ".rb", ".pl",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", "",
}
SLASH_COMMENT_EXT = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".go", ".rs", ".java",
    ".c", ".h", ".cpp", ".cs", ".swift", ".kt", ".jsonc", ".json5",
}
CODE_ESCAPE_EXT = SLASH_COMMENT_EXT | {".py", ".pyw", ".rb"}

_ZERO_WIDTH_RE = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_IFS_RE = re.compile(r"\$\{IFS[^}]*\}|\$IFS\b")
_CONCAT_RE = re.compile(r"""(["'])[ \t]*\+[ \t]*\1""")
_COMPARE_RE = re.compile(r"[!=]==?")
_PIECE_SPLIT_RE = re.compile(r"[\s=:,\[\](){}\"'`;<>，。、；：！？（）「」『』]+")
_ASSIGN_RE = re.compile(r"^[A-Za-z_]\w*=")
_URL_RE = re.compile(r"^(?:https?|ftp)://", re.I)
_PY_NAME_RE = re.compile(r"python[\d.]*|py")


@dataclass(frozen=True)
class Hit:
    """analyze_text 的單筆結果。line 是相對於傳入文字的行號（從 1 起算）。"""

    severity: str
    category: str
    line: int
    detail: str


@dataclass
class Tok:
    value: str  # 去掉引號與跳脫後的內容，用來比對旗標與指令名
    raw: str  # 原文，用來比對路徑
    line: int
    quoted: tuple[str, ...] = ()
    op: bool = False
    names: frozenset[str] | None = None  # _names() 的快取


def normalize_text(text: str) -> str:
    """比對前的正規化：全形轉半形、去零寬字元、展開 $IFS、合併 'a' + 'b' 這種字串相加。"""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _IFS_RE.sub(" ", text)
    return _CONCAT_RE.sub("", text)


def tokenize(text: str, comment: str = "", code_escapes: bool = False) -> list[Tok]:
    """把文字切成 argv 等級的 token。

    處理：單雙引號（引號內容併入同一個 token）、反斜線跳脫、續行（反斜線、反引號、^ 接換行）、
    空白與 Tab、註解（comment 可含 "#" 或 "//"）。引號不跨行：沒關的引號在行尾結束，
    這樣多行字串的內容會被當成一般指令再掃一次，寧可多報。
    """
    toks: list[Tok] = []
    val: list[str] = []
    raw: list[str] = []
    quoted: list[str] = []
    qbuf: list[str] = []
    quote = ""
    line = 1
    start = 1
    i = 0
    n = len(text)
    hash_comment = "#" in comment
    slash_comment = "//" in comment

    def flush() -> None:
        if raw:
            toks.append(Tok("".join(val), "".join(raw), start, tuple(quoted)))
            val.clear()
            raw.clear()
            quoted.clear()

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "\r":
            i += 1
            continue
        if not raw:
            start = line
        if quote:
            if c == "\n":
                quoted.append("".join(qbuf))
                quote = ""
                continue
            if c == "\\" and nxt == "\n" and quote == '"':
                i += 2
                line += 1
                continue
            if c == "\\" and nxt in (quote, "\\") and (quote == '"' or code_escapes):
                val.append(nxt)
                qbuf.append(nxt)
                raw.append(c + nxt)
                i += 2
                continue
            if c == quote:
                quoted.append("".join(qbuf))
                quote = ""
                raw.append(c)
                i += 1
                continue
            val.append(c)
            qbuf.append(c)
            raw.append(c)
            i += 1
            continue
        if c in "\\`^" and (nxt == "\n" or text[i + 1 : i + 3] == "\r\n"):
            i += 2 if nxt == "\n" else 3
            line += 1
            continue
        if c == "\n":
            flush()
            toks.append(Tok("\n", "\n", line, op=True))
            line += 1
            i += 1
            continue
        if c.isspace():
            flush()
            i += 1
            continue
        if not raw:
            if hash_comment and c == "#":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if slash_comment and c == "/" and nxt == "/":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if slash_comment and c == "/" and nxt == "*":
                end = text.find("*/", i + 2)
                end = n if end < 0 else end + 2
                line += text.count("\n", i, end)
                i = end
                continue
        two = text[i : i + 2]
        if two in ("||", "&&", "|&"):
            flush()
            toks.append(Tok(two, two, line, op=True))
            i += 2
            continue
        if c == "&" and (nxt == ">" or (raw and raw[-1].endswith(">"))):
            val.append(c)  # 2>&1、&> 是重導向，不是指令分隔
            raw.append(c)
            i += 1
            continue
        if c in "|;&":
            flush()
            toks.append(Tok(c, c, line, op=True))
            i += 1
            continue
        if (c == "\\" and nxt and nxt != "\n") or (c == "`" and nxt in ("'", '"')):
            val.append(nxt)  # 跳脫字元：下一個字照字面收進來（含 PowerShell 的 `" 與 `'）
            raw.append(c + nxt)
            i += 2
            continue
        if c in "'\"":
            quote = c
            qbuf = []
            raw.append(c)
            i += 1
            continue
        if c in "`^":
            raw.append(c)  # 反引號與 ^ 不進 value：i`ex、c^url 這類跳脫會還原成原指令名
            i += 1
            continue
        val.append(c)
        raw.append(c)
        i += 1
    if quote:
        quoted.append("".join(qbuf))
    flush()
    return toks


def split_pipelines(toks: Iterable[Tok]) -> list[list[list[Tok]]]:
    """回傳 pipeline 清單；每個 pipeline 是用 | 接起來的數個 stage，每個 stage 是一串 token。"""
    pipelines: list[list[list[Tok]]] = []
    pipe: list[list[Tok]] = []
    stage: list[Tok] = []
    prev = ""  # 上一個運算子；中間隔著一般 token 就清空
    for tok in toks:
        if not tok.op:
            stage.append(tok)
            prev = ""
            continue
        is_pipe = tok.value in ("|", "|&")
        if tok.value == "\n" and prev in ("|", "|&"):
            continue  # 行尾的 | 之後換行，管線還沒結束
        if is_pipe and prev == "\n" and not stage and not pipe and pipelines:
            pipe = pipelines.pop()  # 行首的 | 接續上一行（PowerShell 7 的寫法）
            prev = tok.value
            continue
        prev = tok.value
        if stage:
            pipe.append(stage)
        stage = []
        if not is_pipe:
            if pipe:
                pipelines.append(pipe)
            pipe = []
    if stage:
        pipe.append(stage)
    if pipe:
        pipelines.append(pipe)
    return pipelines


def _basename(text: str) -> str:
    text = text.strip().strip("\"'`").replace("\\", "/").lower()
    return text.rstrip("/").rsplit("/", 1)[-1]


_NAME_SPLIT_RE = re.compile(r"[=(`]")
_NAME_CUT_RE = re.compile(r"[(){};]")
_NAME_EXT_RE = re.compile(r"\.(?:exe|cmd|bat|com)$")


def _names(tok: Tok) -> frozenset[str]:
    """token 可能代表的指令名（小寫、去路徑、去 .exe）。value 與 raw 各算一次。"""
    if tok.names is not None:
        return tok.names
    out: set[str] = set()
    for source in {tok.value, tok.raw}:
        # X=$(curl …)、execSync(`curl …`)、iex(irm …) 這類黏在一起的寫法，每一段都算一個候選。
        for text in {source, *_NAME_SPLIT_RE.split(source)}:
            name = text.strip().lower().replace("\\", "/").strip("\"'`")
            if name != ".":
                name = name.lstrip("$({<&@!")
                name = _NAME_CUT_RE.split(name, maxsplit=1)[0]
                name = name.rsplit("/", 1)[-1]
                name = _NAME_EXT_RE.sub("", name)
            if name:
                out.add(name)
    tok.names = frozenset(out)
    return tok.names


def _is_executor(name: str) -> bool:
    return name in EXECUTORS or bool(_PY_NAME_RE.fullmatch(name))


def _head(stage: list[Tok]) -> tuple[int | None, frozenset[str]]:
    """略過 sudo／env 這類包裝與 VAR=value，回傳真正的指令位置與名稱。"""
    wrapped = False
    for idx, tok in enumerate(stage):
        names = _names(tok)
        if names & WRAPPERS:
            wrapped = True
            continue
        if _ASSIGN_RE.match(tok.value) or tok.value in _SHELL_KEYWORDS:
            continue
        if wrapped and tok.value.startswith("-"):
            continue
        return idx, names
    return None, frozenset()


def _all_names(stage: list[Tok]) -> set[str]:
    out: set[str] = set()
    for tok in stage:
        out |= _names(tok)
    return out


def _stage_text(stage: list[Tok]) -> str:
    return " ".join(tok.raw for tok in stage).lower()


def _is_downloader_stage(stage: list[Tok]) -> bool:
    return bool(_all_names(stage) & DOWNLOADERS) or bool(_DL_METHOD_RE.search(_stage_text(stage)))


def _is_decoder_stage(stage: list[Tok]) -> bool:
    _, names = _head(stage)
    return bool(names & DECODERS)


def _is_executor_stage(stage: list[Tok]) -> bool:
    idx, names = _head(stage)
    if idx is None:
        return False
    if any(_is_executor(n) for n in names):
        return True
    every = _all_names(stage)
    if every & _PS_EVAL:
        return True
    return bool(_names(stage[0]) & {"sudo", "doas", "env", "xargs"}) and any(_is_executor(n) for n in every)


def _flag_pieces(stage: list[Tok]) -> list[tuple[str, int, int]]:
    """把 token 再拆成旗標等級的片段：等號、冒號、逗號、括號、引號都當分隔，並轉小寫。

    `==`／`!=` 換成哨兵，讓「比較某個值」不會被當成「設定某個值」。
    """
    pieces: list[tuple[str, int, int]] = []
    for tok in stage:
        value = _COMPARE_RE.sub(" \x00 ", tok.value)
        for piece in _PIECE_SPLIT_RE.split(value):
            piece = piece.rstrip(".!?").lower()
            if piece and piece != "-":  # 單獨的 "-" 是 YAML 清單符號，不能擋在旗標和值中間
                pieces.append((piece, tok.line, id(tok)))
    return pieces


def _slash_command_tokens(pipelines: list[list[list[Tok]]]) -> set[int]:
    """斜線指令（/name …）那一道指令裡的 token。同一道指令只要出現任何 agent CLI 名稱就不算。"""
    out: set[int] = set()
    for pipe in pipelines:
        for stage in pipe:
            head = stage[0]
            if head.quoted or head.value != head.raw or not _SLASH_COMMAND_RE.match(head.value):
                continue
            if _all_names(stage) & AGENT_CLIS:
                continue
            out.update(id(tok) for tok in stage)
    return out


def check_bypass_flags(words: list[Tok], slash_tokens: Iterable[int] = ()) -> list[Hit]:
    """words 是整段文字去掉運算子後的 token。不分行比對，多行寫成的 argv 陣列才配得起來。

    slash_tokens 是 _slash_command_tokens() 的結果，只影響 CONTEXT_FLAGS 裡的旗標。
    """
    hits: list[Hit] = []
    pieces = _flag_pieces(words)
    paired: set[int] = set()
    slash = set(slash_tokens)
    for idx, (piece, line, tok_id) in enumerate(pieces):
        nxt = pieces[idx + 1][0] if idx + 1 < len(pieces) else ""
        if piece in CONTEXT_FLAGS and tok_id in slash:
            hits.append(Hit(REVIEW, CAT_BYPASS, line, f"{piece}（跟在斜線指令後面，可能是該指令自己的模式名稱，不是 agent CLI 的旗標；需人工確認）"))
        elif piece in FAIL_FLAGS:
            hits.append(Hit(FAIL, CAT_BYPASS, line, f"{piece}（{FAIL_FLAGS[piece]}）"))
        elif piece in REVIEW_FLAGS:
            hits.append(Hit(REVIEW, CAT_BYPASS, line, f"{piece}（{REVIEW_FLAGS[piece]}）"))
        elif piece.startswith(_D) and len(piece) > len(_D):
            hits.append(Hit(REVIEW, CAT_BYPASS, line, f"{piece}（不在已知清單的同類旗標）"))
        if (piece, nxt) in FAIL_PAIRS:
            paired.add(idx + 1)
            hits.append(Hit(FAIL, CAT_BYPASS, line, f"{piece} {nxt}（{FAIL_PAIRS[(piece, nxt)]}）"))
        elif (piece, nxt) in REVIEW_PAIRS:
            hits.append(Hit(REVIEW, CAT_BYPASS, line, f"{piece} {nxt}（{REVIEW_PAIRS[(piece, nxt)]}）"))
        elif piece in LONE_VALUES and idx not in paired:
            hits.append(Hit(REVIEW, CAT_BYPASS, line, f"{piece}（單獨出現的危險值，無法判斷用途）"))
    return hits


_LOOPBACK_URL_RE = re.compile(
    r"^(?:https?://)?(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?(?:[/?#][^@\\$`\s]*)?$", re.I
)
# 不帶值、也不改變連線對象的旗標。-L（跟隨轉址）、-K（設定檔）、-x（代理）這類一律不在內。
_LOOPBACK_SAFE_FLAG_RE = re.compile(r"^(?:-[sSfq]+|-q?O-|--silent|--show-error|--fail|--quiet|--no-progress-meter)$")


def _is_loopback_only_download(stage: list[Tok]) -> bool:
    """下載指令的對象是不是只有本機 loopback 位址。

    判斷從嚴：第一個 token 必須就是下載指令本身（前面有環境變數或 sudo 都不算），
    其餘 token 只能是白名單內的旗標或 loopback 網址；出現任何看不懂的東西就回 False。
    """
    if not stage or stage[0].quoted or _NAME_EXT_RE.sub("", stage[0].raw.lower()) not in DOWNLOADERS:
        return False
    urls = 0
    for tok in stage[1:]:
        if tok.raw.strip("\"'") != tok.value:
            return False
        if _LOOPBACK_SAFE_FLAG_RE.match(tok.value):
            continue
        if not _LOOPBACK_URL_RE.match(tok.value):
            return False
        urls += 1
    return urls > 0


def check_pipeline(pipe: list[list[Tok]]) -> list[Hit]:
    hits: list[Hit] = []
    for idx in range(1, len(pipe)):
        stage = pipe[idx]
        if not _is_executor_stage(stage):
            continue
        earlier = pipe[:idx]
        shown = " | ".join(" ".join(t.value for t in s) for s in pipe)[:200]
        sources = [s for s in earlier if _is_downloader_stage(s)]
        if sources and all(_is_loopback_only_download(s) for s in sources):
            hits.append(Hit(REVIEW, CAT_REMOTE, stage[0].line, f"本機 loopback 位址的回應接管線交給直譯器（不是遠端內容，仍需確認該本機服務可信）：{shown}"))
        elif sources:
            hits.append(Hit(FAIL, CAT_REMOTE, stage[0].line, f"遠端內容接管線執行：{shown}"))
        elif any(_is_decoder_stage(s) for s in earlier):
            hits.append(Hit(FAIL, CAT_OBFUSCATED, stage[0].line, f"解碼後接管線執行：{shown}"))
    return hits


def check_substitution(stage: list[Tok]) -> list[Hit]:
    """bash -c "$(curl …)"、bash <(curl …)、iex (irm …)、exec(urlopen(…)) 這類不經管線的寫法。"""
    text = _stage_text(stage)
    shown = " ".join(t.value for t in stage)[:200]
    idx, names = _head(stage)
    if idx is not None and (any(_is_executor(n) for n in names) or _all_names(stage) & _PS_EVAL):
        if _SUBST_DL_RE.search(text):
            return [Hit(FAIL, CAT_REMOTE, stage[0].line, f"遠端內容經指令替換後執行：{shown}")]
    if _CODE_EXEC_RE.search(text) and _CODE_FETCH_RE.search(text):
        return [Hit(FAIL, CAT_REMOTE, stage[0].line, f"程式內下載後直接執行：{shown}")]
    return []


def check_encoded_command(stage: list[Tok]) -> list[Hit]:
    idx, names = _head(stage)
    if idx is None or not names & {"powershell", "pwsh"}:
        return []
    for tok in stage[idx + 1 :]:
        flag = tok.value.lower()
        if flag == "-ec" or (len(flag) >= 2 and flag.startswith("-e") and "-encodedcommand".startswith(flag)):
            shown = " ".join(t.value for t in stage)[:120]
            return [Hit(FAIL, CAT_OBFUSCATED, tok.line, f"PowerShell 編碼指令無法靜態判讀：{shown}")]
    return []


_DYNAMIC_EVALS = {"iex", "invoke-expression", "eval"}
_DYNAMIC_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "pwsh", "powershell"}
_DYNAMIC_CMD_FLAGS = {"-c", "-lc", "-ic", "-command", "-cmd"}
_DYNAMIC_CALL_RE = re.compile(r"(?<![.\w])(?:eval|exec)\s*\(\s*(?![\"'`)\s])")


def check_dynamic_exec(stage: list[Tok]) -> list[Hit]:
    """執行「非字面內容」的寫法：內容在執行期才決定，靜態無法判讀，只列 REVIEW。"""
    shown = " ".join(t.value for t in stage)[:160]
    idx, names = _head(stage)
    if idx is not None:
        rest = stage[idx + 1 :]
        if names & _DYNAMIC_EVALS:
            if any("$" in t.raw or "`" in t.raw for t in rest if not t.op):
                return [Hit(REVIEW, CAT_DYNAMIC, stage[0].line, f"執行非字面內容（內容在執行期才決定）：{shown}")]
        elif names & _DYNAMIC_SHELLS:
            for pos, tok in enumerate(rest[:-1]):
                if tok.value.lower() in _DYNAMIC_CMD_FLAGS and ("$" in rest[pos + 1].raw or "`" in rest[pos + 1].raw):
                    return [Hit(REVIEW, CAT_DYNAMIC, stage[0].line, f"直譯器 -c 執行非字面內容：{shown}")]
    if _DYNAMIC_CALL_RE.search(" ".join(t.raw for t in stage)):
        return [Hit(REVIEW, CAT_DYNAMIC, stage[0].line, f"eval／exec 呼叫的參數不是字面字串：{shown}")]
    return []


def _downloaded_names(stage: list[Tok]) -> set[str]:
    out: set[str] = set()
    for idx, tok in enumerate(stage):
        value = tok.value
        nxt = stage[idx + 1].value if idx + 1 < len(stage) else ""
        if value in ("-o", "-O", "--output", "--output-document") or value.lower() in ("-outfile", "-out"):
            out.add(_basename(nxt))
        elif value.startswith(("--output=", "--output-document=")):
            out.add(_basename(value.split("=", 1)[1]))
        elif value.startswith(">"):
            out.add(_basename(value.lstrip(">") or nxt))
        elif _URL_RE.match(value):
            out.add(_basename(value.split("?", 1)[0].split("#", 1)[0]))
    return {name for name in out if name and name not in {"-", "null", "stdout", "nul"} and not name.startswith("-")}


def check_download_then_run(stage: list[Tok], downloaded: dict[str, int]) -> list[Hit]:
    idx, names = _head(stage)
    if idx is None or not downloaded:
        return []
    head_base = _basename(stage[idx].raw)
    target = ""
    if head_base in downloaded:
        target = head_base
    elif any(_is_executor(n) for n in names):
        for tok in stage[idx + 1 :]:
            if tok.value.startswith("-"):
                continue
            if _basename(tok.raw) in downloaded:
                target = _basename(tok.raw)
            break  # 只看第一個非旗標參數（腳本位置），避免把資料檔當成被執行
    if not target:
        return []
    shown = " ".join(t.value for t in stage)[:160]
    return [Hit(FAIL, CAT_REMOTE, stage[0].line, f"下載後執行（第 {downloaded[target]} 行下載 {target}）：{shown}")]


def check_credentials(toks: list[Tok]) -> list[Hit]:
    words = [tok for tok in toks if not tok.op]
    if not words:
        return []
    offsets: list[int] = []
    parts: list[str] = []
    pos = 0
    for tok in words:
        part = re.sub(r"[\"'`]", "", tok.raw.replace("\\", "/").lower())
        offsets.append(pos)
        parts.append(part)
        pos += len(part) + 1
    text = re.sub(r"/{2,}", lambda m: "/" + " " * (len(m.group()) - 1), " ".join(parts))
    hits: list[Hit] = []
    for pattern, label in CRED_PATTERNS:
        for match in pattern.finditer(text):
            tok = words[max(0, bisect_right(offsets, match.start()) - 1)]
            shown = match.group()[-80:].strip()
            groups = match.groupdict()
            # 瀏覽器名稱和檔名之間完全沒有斜線、緊貼檔名的分隔也只有空白，就是在講話，不是路徑。
            if groups.get("gap") is not None and "/" not in groups["gap"] and not re.search(r"[/,+]", groups["sep"]):
                hits.append(Hit(REVIEW, CAT_CRED, tok.line, f"看起來是說明文字而不是路徑（兩者之間沒有路徑分隔），需人工確認：{label}：{shown}"))
                continue
            hits.append(Hit(FAIL, CAT_CRED, tok.line, f"{label}：{shown}"))
    return hits


# ---------------------------------------------------------------------------
# 移除或關閉系統防護
# ---------------------------------------------------------------------------

_PS_FALSE = {"$false", "false", "0"}
_ZERO = {"0", "0x0", "0x00000000"}
_ONE = {"1", "0x1", "0x00000001"}
_UAC_KEY_RE = re.compile(r"\b(?:enablelua|consentpromptbehavioradmin|promptonsecuredesktop)\b")
_DEFENDER_KEY_RE = re.compile(r"\bdisable(?:antispyware|antivirus|realtimemonitoring|behaviormonitoring)\b")
_FIREWALL_OFF_RE = re.compile(r"firewall\b.*\bstate\s+off\b|firewall\s+set\s+opmode\s+(?:mode=)?disable")
_MOTW_REMOVERS = {"remove-item", "ri", "rm", "del", "erase", "clear-content"}
_REG_WRITERS = {"reg", "set-itemproperty", "sp", "new-itemproperty"}


def _value_after(rest: list[str], keys: tuple[str, ...]) -> str:
    """`/d 0`、`-Value 0`、`-Value:0` 這類「鍵 值」的值；找不到回空字串。"""
    for pos, item in enumerate(rest):
        key, _, inline = item.partition(":")
        if key in keys:
            return inline or (rest[pos + 1] if pos + 1 < len(rest) else "")
    return ""


def check_defense_off(stage: list[Tok]) -> list[Hit]:
    """會讓作業系統不再檢查下載內容、或直接關掉防護的指令。只認動作，查詢與重新開啟不算。"""
    idx, names = _head(stage)
    if idx is None:
        return []
    rest = [tok.value.lower() for tok in stage[idx + 1 :]]
    text = _stage_text(stage)
    why = ""
    if "xattr" in names:
        short = [item for item in rest if re.fullmatch(r"-[a-z]+", item)]
        if any("c" in item for item in short):
            why = "清除全部延伸屬性，連 macOS 隔離標記一起拿掉"
        elif any("d" in item for item in short) and "com.apple.quarantine" in text:
            why = "移除 macOS 隔離屬性，Gatekeeper 不再檢查"
    elif "spctl" in names:
        if any(item in ("--master-disable", "--global-disable", "--disable") for item in rest):
            why = "關閉 macOS Gatekeeper"
    elif "csrutil" in names:
        if "disable" in rest:
            why = "關閉 macOS 系統完整性保護（SIP）"
    elif names & {"set-mppreference", "add-mppreference"}:
        for pos, item in enumerate(rest):
            key, _, inline = item.partition(":")
            value = inline or (rest[pos + 1] if pos + 1 < len(rest) else "")
            if key.startswith("-disable") and value not in _PS_FALSE:
                why = "關閉 Microsoft Defender 的防護項目"
            elif key.startswith("-exclusion"):
                why = "新增 Microsoft Defender 排除項目"
    elif "unblock-file" in names or (names & _MOTW_REMOVERS and "zone.identifier" in text):
        why = "移除 Windows 的網路下載標記，SmartScreen 不再檢查"
    elif names & _REG_WRITERS and "query" not in rest[:1]:
        value = _value_after(rest, ("/d", "-value"))
        if _UAC_KEY_RE.search(text) and value in _ZERO:
            why = "關閉或降低 Windows UAC"
        elif _DEFENDER_KEY_RE.search(text) and value in _ONE:
            why = "用登錄檔關閉 Microsoft Defender"
    elif "netsh" in names:
        if _FIREWALL_OFF_RE.search(text):
            why = "關閉 Windows 防火牆"
    elif "set-netfirewallprofile" in names:
        if _value_after(rest, ("-enabled",)) in _PS_FALSE:
            why = "關閉 Windows 防火牆"
    if not why:
        return []
    shown = " ".join(t.value for t in stage)[:160]
    return [Hit(FAIL, CAT_DEFENSE, stage[0].line, f"{why}：{shown}")]


# ---------------------------------------------------------------------------
# clone 後執行其中的安裝程式、改寫 shell 啟動檔（都需要跨指令的狀態，只在最外層做）
# ---------------------------------------------------------------------------


@dataclass
class _Clone:
    line: int
    keys: set[str]  # "$變數名" 或目錄名（小寫）
    entered: bool = False  # 之後有沒有 cd 進去


@dataclass
class _ScriptState:
    clones: list[_Clone] = field(default_factory=list)
    profile_vars: set[str] = field(default_factory=set)


_GIT_VALUE_FLAGS = {
    "--depth", "-b", "--branch", "-o", "--origin", "-c", "--config", "--reference", "--separate-git-dir",
    "--template", "-j", "--jobs", "--shallow-since", "--shallow-exclude", "-u", "--upload-pack", "--filter",
}
_VAR_REF_RE = re.compile(r"\$\{?([a-z_]\w*)|%([a-z_]\w*)%")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_INSTALLER_RE = re.compile(r"(?:^|[/\\\s\"'(])(?:install|setup|bootstrap)[\w.-]*\.(?:sh|bash|zsh|ps1|py|bat|cmd|js|mjs)\b")
_CD_NAMES = {"cd", "pushd", "set-location", "sl", "chdir"}
_NOT_RUNNING = {
    "cat", "ls", "dir", "less", "more", "head", "tail", "grep", "rg", "test", "[", "[[", "chmod", "chown", "echo",
    "printf", "cp", "mv", "rm", "sed", "type", "get-content", "gc", "test-path", "write-host", "write-output", "git",
}


def _clone_keys(stage: list[Tok], idx: int) -> set[str] | None:
    """git clone 的目的地；不是 clone 回 None。"""
    rest = stage[idx + 1 :]
    pos = next((i for i, tok in enumerate(rest) if tok.value.lower() == "clone"), None)
    if pos is None:
        return None
    args: list[Tok] = []
    skip = False
    for tok in rest[pos + 1 :]:
        if skip:
            skip = False
        elif tok.value.startswith("-"):
            skip = tok.value.lower() in _GIT_VALUE_FLAGS
        else:
            args.append(tok)
    if not args:
        return set()
    dest = args[1] if len(args) > 1 else args[0]
    variables = {a or b for a, b in _VAR_REF_RE.findall(dest.raw.lower())}
    if variables:
        return {"$" + name for name in variables}
    base = _basename(dest.raw).rsplit(":", 1)[-1]
    if len(args) == 1:
        base = re.sub(r"\.git$", "", base)
    return {base} if base else set()


def _mentions(text: str, key: str) -> bool:
    if key.startswith("$"):
        name = re.escape(key[1:])
        return bool(re.search(rf"\$\{{?{name}\b|%{name}%", text))
    return bool(re.search(rf"(?:^|[/\\\s\"'(]){re.escape(key)}(?:[/\\\s\"')]|$)", text))


def check_clone_then_run(stage: list[Tok], state: _ScriptState) -> list[Hit]:
    """git clone 之後直接執行 clone 下來的安裝程式，中間沒有 checkout 到 commit。只列 REVIEW。

    分支與標籤（--branch）可以被上游改指向，不算固定；要 checkout／reset／switch 到 commit 雜湊才算。
    """
    idx, names = _head(stage)
    if idx is None:
        return []
    text = _stage_text(stage)
    if "git" in names:
        values = [tok.value.lower() for tok in stage[idx + 1 :]]
        keys = _clone_keys(stage, idx)
        if keys is not None:
            state.clones.append(_Clone(stage[0].line, keys))
        elif {"checkout", "reset", "switch"} & set(values) and any(_COMMIT_RE.match(v) for v in values):
            state.clones.clear()
        return []
    if not state.clones:
        return []
    if names & _CD_NAMES:
        for clone in state.clones:
            if any(_mentions(text, key) for key in clone.keys):
                clone.entered = True
        return []
    if names & _NOT_RUNNING or not _INSTALLER_RE.search(text):
        return []
    for clone in state.clones:
        if clone.entered or any(_mentions(text, key) for key in clone.keys):
            shown = " ".join(t.value for t in stage)[:160]
            detail = f"clone 後直接執行其中的安裝程式，沒有固定到 commit（第 {clone.line} 行 clone）；執行的是上游當下的內容，不在本次掃描範圍：{shown}"
            return [Hit(REVIEW, CAT_REMOTE, stage[0].line, detail)]
    return []


_PROFILE_RE = re.compile(
    r"(?:^|[/\\\s\"'=])(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zshenv|\.zprofile|\.profile|config\.fish"
    r"|microsoft\.powershell_profile\.ps1|profile\.ps1)(?![\w.])|\$\{?profile\b"
)
_REDIRECT_RE = re.compile(r"^\d?>>?(.*)$")
_FILE_WRITERS = {"tee", "tee-object", "add-content", "ac", "out-file", "set-content"}


def check_profile_write(stage: list[Tok], state: _ScriptState) -> list[Hit]:
    """寫入 shell／PowerShell 啟動檔（之後每開一個 shell 都會載入）。讀取與 source 不算。只列 REVIEW。"""

    def is_profile(raw: str) -> bool:
        low = raw.lower()
        return bool(_PROFILE_RE.search(low)) or any(_mentions(low, "$" + name) for name in state.profile_vars)

    # 先記下「值是啟動檔路徑」的變數：RC="$HOME/.zshrc"、$target = $PROFILE.CurrentUserAllHosts
    for tok in stage:
        if _ASSIGN_RE.match(tok.value) and is_profile(tok.raw.split("=", 1)[1]):
            state.profile_vars.add(tok.value.split("=", 1)[0].lower())
    if len(stage) >= 3 and stage[0].value.startswith("$") and stage[1].value == "=":
        if any(is_profile(tok.raw) for tok in stage[2:]):
            state.profile_vars.add(stage[0].value[1:].lower())
        return []

    idx, names = _head(stage)
    written = False
    for pos, tok in enumerate(stage):
        match = _REDIRECT_RE.match(tok.raw)
        if match:
            target = match.group(1) or (stage[pos + 1].raw if pos + 1 < len(stage) else "")
            written = written or is_profile(target)
    if idx is not None:
        rest = stage[idx + 1 :]
        if names & _FILE_WRITERS or ("sed" in names and any(t.value.startswith("-i") for t in rest)):
            written = written or any(is_profile(tok.raw) for tok in rest)
    if not written:
        return []
    shown = " ".join(t.value for t in stage)[:160]
    return [Hit(REVIEW, CAT_PERSIST, stage[0].line, f"改寫 shell／PowerShell 啟動檔，之後每開一個 shell 都會載入：{shown}")]


def analyze_text(text: str, comment: str = "", code_escapes: bool = False, _depth: int = 0) -> list[Hit]:
    """把一段文字當成「會被執行的內容」來分析，回傳所有命中。"""
    toks = tokenize(normalize_text(text), comment=comment, code_escapes=code_escapes)
    hits: list[Hit] = []
    downloaded: dict[str, int] = {}
    pipelines = split_pipelines(toks)
    hits += check_bypass_flags([tok for tok in toks if not tok.op], _slash_command_tokens(pipelines))
    state = _ScriptState()
    for pipe in pipelines:
        hits += check_pipeline(pipe)
        for stage in pipe:
            hits += check_substitution(stage)
            hits += check_encoded_command(stage)
            hits += check_dynamic_exec(stage)
            hits += check_defense_off(stage)
            if _depth == 0:
                hits += check_clone_then_run(stage, state)
                hits += check_profile_write(stage, state)
                hits += check_download_then_run(stage, downloaded)
                if _all_names(stage) & DOWNLOADERS:
                    for name in _downloaded_names(stage):
                        downloaded.setdefault(name, stage[0].line)
            if _depth < MAX_NESTING:
                # 引號裡還有完整指令（bash -c "…"、os.system("…")）就往內再分析一層。
                for tok in stage:
                    for inner in tok.quoted:
                        if re.search(r"[\s|]", inner):
                            for hit in analyze_text(inner, _depth=_depth + 1):
                                hits.append(Hit(hit.severity, hit.category, tok.line + hit.line - 1, hit.detail))
    if _depth == 0:
        hits += check_credentials(toks)
    seen: set[Hit] = set()
    unique: list[Hit] = []
    for hit in hits:
        if hit not in seen:
            seen.add(hit)
            unique.append(hit)
    return unique


def analyze_mention(text: str) -> list[Hit]:
    """說明文字：同樣的偵測，但一律降成 REVIEW，因為無法分辨是「叫你這樣做」還是「叫你別這樣做」。"""
    out: list[Hit] = []
    for hit in analyze_text(text) + defense_off_in_prose(text):
        out.append(Hit(REVIEW, hit.category, hit.line, "說明文字提及，需人工判斷是指示還是警告：" + hit.detail))
    return out


def defense_off_in_prose(text: str) -> list[Hit]:
    """說明文字裡的移除防護指令。

    說明文字的指令常接在「Then:」「Run」「先執行」之後，不在行首，所以逐個 token 當作指令開頭再檢查一次
    （行首那個位置 analyze_text 已經查過）。只用在說明文字與 Markdown 程式碼區塊的 REVIEW 判定，
    腳本與設定檔的 FAIL 判定不受影響。
    """
    hits: list[Hit] = []
    for pipe in split_pipelines(tokenize(normalize_text(text))):
        for stage in pipe:
            for idx in range(1, len(stage)):
                hits += check_defense_off(stage[idx:])
    return hits


# ---------------------------------------------------------------------------
# 寫給 agent（或叫使用者照做）的指示文字。全部只列 REVIEW：
# 句型比對分不出「叫你這樣做」和「叫你別這樣做」，也認不出換句話說的寫法。
# ---------------------------------------------------------------------------

_TOOLS = r"(?:tools?|browsers?|skills?|mcp|agents?|search|fetch(?:er)?|plugins?|commands?)"
_BUILTIN = r"(?:built-?in|native|other|default|stock|alternative)"
_THIS = r"this (?:skill|tool|plugin|server|agent)"
_ASK = r"(?:ask(?:ing)?|request(?:ing)?|prompt(?:ing)?|seek(?:ing)?|wait(?:ing)? for|re-?ask(?:ing)?|re-?confirm(?:ing)?|confirm(?:ing)?|paus(?:e|ing) for)"
_CONSENT = r"(?:permissions?|authori[sz]ation|approval|confirmation|consent|sign-?off)"
_NO_TURN = r"(?:(?!\b(?:without|unless|until|before)\b|[.;!?]\s| - ).)"  # 語意會反過來的詞與句子邊界都不跨過去
_ZH_ASK = r"(?:詢問|询问|請求|请求|要求|徵求|征求|等待|等候)"
_ZH_CONSENT = r"(?:授權|授权|核准|許可|许可|同意|確認|确认|批准|審批|审批)"
_ZH_BUILTIN = r"(?:內建|内置|内建|其他|其它|原生)"
_DEFENSES = (
    r"(?:windows defender|microsoft defender|defender|antivirus|anti-virus|real-?time protection|uac"
    r"|user account control|gatekeeper|smartscreen|firewall|system integrity protection|tamper protection)"
)

_LABEL_PREEMPT = "要求 agent 預設用它、優先於或取代其他工具"
_LABEL_NO_ASK = "要求 agent 不必再向使用者請求授權／核准"
_LABEL_REMOTE = "叫 agent 讀遠端網址並照上面的指示做（內容隨時可改）"
_LABEL_RUNTIME = "真正的指引在執行期由已安裝的程式印出，審查目錄看不到"
_LABEL_COOKIE = "把瀏覽器的 Cookie 複製／注入自動化工作階段的登入做法"
_LABEL_CLICK = "叫使用者略過或關閉系統防護"

# (類別, 說明, 樣式, 是否只看 agent 會載入的檔案)。比對對象已轉小寫、去掉 Markdown 強調符號。
INSTRUCTION_RULES: list[tuple[str, str, re.Pattern[str], bool]] = [
    (CAT_STEER, _LABEL_PREEMPT, re.compile(
        rf"\b(?:prefer|prioriti[sz]e|favou?r|always use|use|choose|reach for)\b.{{0,80}}?\b(?:over|instead of|rather than)\b"
        rf".{{0,40}}?\b{_BUILTIN}\b.{{0,40}}?\b{_TOOLS}\b"
    ), False),
    (CAT_STEER, _LABEL_PREEMPT, re.compile(
        rf"\b(?:read|use|invoke|load|trigger|activate|consult)\s+{_THIS}\b.{{0,60}}?\bby default\b"
        rf"|\bby default,?\s.{{0,40}}?\b(?:read|use|invoke|load|trigger|activate|consult)\s+{_THIS}\b"
        rf"|\bdefault to (?:using |reading |loading )?{_THIS}\b"
    ), False),
    (CAT_STEER, _LABEL_PREEMPT, re.compile(
        rf"\btakes? (?:priority|precedence) over\b.{{0,30}}?\b(?:other|built-?in|native|all|any)\b.{{0,20}}?\b(?:{_TOOLS}|instructions?)"
        rf"|\b(?:do not|don't|never|avoid|stop)\s+us(?:e|ing)\b.{{0,40}}?\b(?:built-?in|native|default|stock)\b.{{0,30}}?\b{_TOOLS}\b"
        rf"|\b(?:replaces?|in place of|supersedes?)\b.{{0,30}}?\b(?:built-?in|native|default)\b.{{0,30}}?\b{_TOOLS}\b"
    ), False),
    (CAT_STEER, _LABEL_PREEMPT, re.compile(
        rf"(?:優先|优先|預設|默认|一律|務必|务必|總是|总是|必須|必须).{{0,20}}?(?:使用|讀|读|呼叫|調用|调用|載入|加载)"
        rf".{{0,40}}?(?:而不是|而非|不要用|勿用|代替|取代).{{0,20}}?{_ZH_BUILTIN}"
        rf"|(?:取代|代替|優先於|优先于).{{0,10}}?{_ZH_BUILTIN}.{{0,20}}?(?:工具|瀏覽器|浏览器|技能|搜尋|搜索)"
    ), False),
    (CAT_STEER, _LABEL_NO_ASK, re.compile(
        rf"\b(?:do not|don't|dont|never|no need to|need not|needn't|must not|should not|shouldn't)\b{_NO_TURN}{{0,50}}?"
        rf"\b{_ASK}\b{_NO_TURN}{{0,60}}?\b{_CONSENT}\b"
        rf"|\b(?:stop|skip|avoid)\s+(?:asking|requesting|prompting|waiting)\b.{{0,60}}?\b{_CONSENT}\b"
    ), False),
    (CAT_STEER, _LABEL_NO_ASK, re.compile(
        rf"\b(?:constitutes?|counts? as|is treated as|implies|assumes?|assumed|deem(?:s|ed)?)\b.{{0,50}}?"
        rf"\b(?:authori[sz]ation|permission|approval|consent)\b"
        r"|\breplaces?\b.{0,40}?\b(?:user|human)\b.{0,20}?\b(?:approval|confirmation|sign-?off)\b"
    ), False),
    (CAT_STEER, _LABEL_NO_ASK, re.compile(
        rf"(?:不要|不用|不必|不需|無需|无需|無須|无须|毋須|別|别|勿)(?:再|另外|額外|额外)?.{{0,12}}?{_ZH_ASK}.{{0,15}}?{_ZH_CONSENT}"
        rf"|(?:視為|视为|等同|即代表).{{0,12}}?(?:授權|授权|同意|核准|批准)"
    ), False),
    (CAT_STEER, _LABEL_REMOTE, re.compile(
        r"\b(?:read|fetch|open|visit|load|download|go to|browse(?: to)?)\b.{0,60}?https?://\S+.{0,80}?"
        r"\b(?:follow|execute|carry out|obey|do what|do as)\b"
        r"|\bfollow\b.{0,40}?\b(?:instructions?|steps?|guide|directions)\b.{0,30}?\b(?:at|in|from|on)\b.{0,15}?https?://"
        r"|(?:讀|读|閱讀|阅读|打開|打开|開啟|抓取|訪問|访问|前往).{0,30}?https?://\S+.{0,40}?(?:照|按照|依照|遵循|依)"
        r".{0,12}?(?:做|執行|执行|指示|步驟|步骤|操作|說明|说明)"
    ), False),
    (CAT_STEER, _LABEL_RUNTIME, re.compile(
        r"\b(?:run|execute|invoke|call)\b.{0,80}?\b(?:to|and|then)\b.{0,30}?\b(?:load|get|print|fetch|read|follow|obtain|retrieve|see)\b"
        r".{0,40}?\b(?:instructions|guidance|skill body|skill content|usage guide|playbook|operating manual)\b"
        r"|\bfollow\b.{0,20}?\b(?:what|whatever)\b.{0,15}?\b(?:it|the command|the cli|the tool)\b.{0,10}?\b(?:prints?|outputs?|returns?|says)\b"
        r"|(?:執行|执行|运行|運行).{0,40}?(?:印出|輸出|输出|打印).{0,20}?(?:指引|指示|說明|说明|技能)"
    ), True),
    (CAT_CRED, _LABEL_COOKIE, re.compile(
        r"\b(?:copy|paste|export|grab|extract|inject|import|reuse|transfer|dump)\b.{0,60}?\bcookies?\b.{0,80}?"
        r"\b(?:browser|devtools|dev tools|chrome|network tab|request headers?|logged-?in session)"
        r"|\b(?:inject|load|import|add)\b.{0,30}?\bcookies?\b.{0,40}?\b(?:into|to)\b.{0,30}?"
        r"\b(?:session|context|agent-browser|playwright|puppeteer|automation|headless|browser)\b"
        r"|(?:複製|复制|貼上|粘贴|注入|匯出|导出|匯入|导入).{0,25}?cookie"
        r"|cookie.{0,25}?(?:複製|复制|貼|粘贴|注入|匯出|导出|匯入|导入)(?:進|进|到|至|入)"
    ), False),
    (CAT_DEFENSE, _LABEL_CLICK, re.compile(
        r"\bsmartscreen\b.{0,120}?(?:run anyway|more info|仍要執行|仍要执行)|(?:run anyway|仍要執行|仍要执行).{0,120}?\bsmartscreen\b"
        r"|\b(?:gatekeeper|unidentified developer|privacy & security)\b.{0,120}?(?:open anyway|仍要打開|仍要打开)"
        r"|(?:open anyway|仍要打開|仍要打开).{0,80}?\b(?:gatekeeper|unidentified developer|privacy & security)\b"
        rf"|\b(?:disable|disabling|turn off|turning off|switch off|deactivate)\b.{{0,40}}?\b{_DEFENSES}\b"
        r"|(?:關閉|关闭|停用|關掉|关掉|暫停|暂停|禁用).{0,15}?(?:防毒|杀毒|殺毒|defender|即時保護|实时保护|uac"
        r"|使用者帳戶控制|用户账户控制|gatekeeper|smartscreen|防火牆|防火墙|系統完整性保護)"
    ), False),
]
_INSTRUCTION_HINT_RE = re.compile(
    r"instead of|rather than|\bover\b|by default|default to|precedence|priority|built-?in|native|\bask|request|prompt|confirm"
    r"|wait|authori|permission|approval|consent|https?://|\bfollow|cookie|smartscreen|gatekeeper|anyway|disabl|turn(?:ing)? off"
    r"|switch off|deactivate|unidentified|instruction|guidance|print|output|playbook|manual|usage guide|[\u4e00-\u9fff]"
)
_MD_EMPHASIS_RE = re.compile(r"[*`]+")
_AGENT_FILE_NAMES = {"skill.md", "agents.md", "claude.md", "gemini.md", "copilot-instructions.md", ".cursorrules"}
_AGENT_DIRS = {"skills", "commands", "agents", "rules", "prompts", "skill-body"}


def is_agent_file(rel: str) -> bool:
    """agent 會直接載入當指示的檔案：SKILL.md、AGENTS.md 之類，或放在 skills/、commands/ 等目錄下的說明檔。"""
    parts = [p.lower() for p in rel.replace("\\", "/").split("/")]
    name = parts[-1]
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return name in _AGENT_FILE_NAMES or (ext in MARKDOWN_EXT and bool(set(parts[:-1]) & _AGENT_DIRS))


def analyze_instructions(text: str, agent_file: bool = False) -> list[Hit]:
    """找寫給 agent（或叫使用者照做）的指示句型，一律 REVIEW。

    以段落為單位比對：連續的非空行接成一行，折行的句子才配得起來；空行不跨。
    """
    hits: list[Hit] = []
    lines = normalize_text(text).replace("\r", "").split("\n")
    idx = 0
    while idx < len(lines):
        if not lines[idx].strip():
            idx += 1
            continue
        start = idx
        offsets: list[int] = []
        parts: list[str] = []
        pos = 0
        while idx < len(lines) and lines[idx].strip():
            part = re.sub(r"\s+", " ", _MD_EMPHASIS_RE.sub("", lines[idx]).strip()).lower().replace("\u2019", "'")
            offsets.append(pos)
            parts.append(part)
            pos += len(part) + 1
            idx += 1
        para = " ".join(parts)
        if not _INSTRUCTION_HINT_RE.search(para):
            continue
        for category, label, pattern, agent_only in INSTRUCTION_RULES:
            if agent_only and not agent_file:
                continue
            for match in pattern.finditer(para):
                line = start + max(0, bisect_right(offsets, match.start()) - 1) + 1
                hits.append(Hit(REVIEW, category, line, f"{label}：{match.group()[:160]}"))
    return hits


# ---------------------------------------------------------------------------
# 逐檔掃描
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    file: str
    where: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "category": self.category, "file": self.file, "where": self.where, "detail": self.detail}


@dataclass
class Unscanned:
    file: str
    reason: str
    sha256: str = ""
    acknowledged: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "reason": self.reason, "sha256": self.sha256, "acknowledged": self.acknowledged}


@dataclass
class PackReport:
    pack: str
    scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unscanned: list[Unscanned] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fails(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == FAIL]

    def reviews(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == REVIEW]

    def blocking_unscanned(self) -> list[Unscanned]:
        return [u for u in self.unscanned if not u.acknowledged]

    def as_dict(self) -> dict[str, Any]:
        return {
            "pack": self.pack,
            "scanned_files": len(self.scanned),
            "findings": [f.as_dict() for f in self.findings],
            "unscanned": [u.as_dict() for u in self.unscanned],
            "errors": self.errors,
            "notes": self.notes,
        }


def _to_findings(hits: Iterable[Hit], rel: str, line_offset: int = 0, where: str = "") -> list[Finding]:
    return [Finding(h.severity, h.category, rel, where or f"第 {h.line + line_offset} 行", h.detail) for h in hits]


def _comment_style(ext: str) -> str:
    if ext in SLASH_COMMENT_EXT:
        return "//"
    if ext in HASH_COMMENT_EXT:
        return "#"
    return ""  # .bat／.cmd 與不認得的副檔名不剝註解，寧可多報


def scan_script(rel: str, text: str, ext: str) -> list[Finding]:
    findings = _to_findings(analyze_text(text, comment=_comment_style(ext), code_escapes=ext in CODE_ESCAPE_EXT), rel)
    return findings + _to_findings(analyze_instructions(text, is_agent_file(rel)), rel)


_FENCE_RE = re.compile(r"^[ \t>]*(`{3,}|~{3,})\s*([^\s`]*)")
_INLINE_EXEC_RE = re.compile(r"!`([^`\n]+)`")
_BLOCK_SCALAR = {"|", ">", "|-", ">-", "|+", ">+"}


def _frontmatter_hook_commands(lines: list[str]) -> tuple[bool, list[tuple[int, str]]]:
    """YAML frontmatter 裡 hooks: 區塊的 command 值。只支援區塊式寫法（標準函式庫沒有 YAML 解析器）。"""
    commands: list[tuple[int, str]] = []
    in_hooks = False
    has_hooks = False
    idx = 0
    while idx < len(lines):
        ln = lines[idx]
        if re.match(r"^hooks\s*:", ln):
            in_hooks = has_hooks = True
        elif in_hooks and re.match(r"^[^\s#-]", ln):
            in_hooks = False
        elif in_hooks:
            match = re.match(r"^(\s*)-?\s*command\s*:\s*(.*)$", ln)
            if match:
                value = match.group(2).strip()
                if value in _BLOCK_SCALAR:
                    indent = len(match.group(1))
                    body: list[str] = []
                    while idx + 1 < len(lines) and (not lines[idx + 1].strip() or len(lines[idx + 1]) - len(lines[idx + 1].lstrip()) > indent):
                        idx += 1
                        body.append(lines[idx].strip())
                    value = "\n".join(body)
                elif len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                commands.append((idx + 1, value))
        idx += 1
    return has_hooks, commands


def scan_markdown(rel: str, text: str) -> list[Finding]:
    """Markdown：圍欄程式碼區塊視為可執行（FAIL），其餘說明文字與行內程式碼降級為 REVIEW。"""
    findings: list[Finding] = []
    lines = text.split("\n")
    body_start = 0
    if lines and lines[0].strip() == "---":
        for idx in range(1, len(lines)):
            if lines[idx].strip() in ("---", "..."):
                front = lines[1:idx]
                body_start = idx + 1
                has_hooks, commands = _frontmatter_hook_commands(front)
                for line_no, command in commands:
                    where = f"第 {line_no + 1} 行（frontmatter hooks）"
                    findings.append(Finding(REVIEW, CAT_HOOK, rel, where, f"frontmatter command hook：{command[:200]}"))
                    findings += _to_findings(analyze_text(command, comment="#"), rel, where=where)
                if has_hooks and not commands:
                    findings.append(Finding(REVIEW, CAT_HOOK, rel, "frontmatter", "frontmatter 有 hooks 但解析不出 command，請人工檢視"))
                for offset, ln in enumerate(front):
                    findings += _to_findings(analyze_mention(ln), rel, line_offset=offset + 1)
                break

    fence = ""
    block: list[str] = []
    block_start = 0
    block_lang = ""

    def close_block() -> None:
        lang = block_lang.lower().lstrip("{.")
        if lang.startswith("!"):
            findings.append(Finding(REVIEW, CAT_HOOK, rel, f"第 {block_start} 行", "技能載入時自動執行的指令區塊：" + " ⏎ ".join(block)[:200]))
            lang = lang[1:]
        if lang in ("bat", "cmd", "batch", "dos"):
            comment = ""
        elif lang in ("js", "javascript", "ts", "typescript", "jsx", "tsx", "jsonc", "json5"):
            comment = "//"
        else:
            comment = "#"
        hits = analyze_text("\n".join(block), comment=comment, code_escapes=comment == "//" or lang in ("py", "python"))
        findings.extend(_to_findings(hits, rel, line_offset=block_start))
        # 區塊裡指令前面接了說明字樣（Then:／Run）的寫法，只列 REVIEW。
        extra = defense_off_in_prose("\n".join(block))
        findings.extend(
            _to_findings(
                [Hit(REVIEW, h.category, h.line, "指令前有其他文字，需人工判斷是指示還是警告：" + h.detail) for h in extra],
                rel,
                line_offset=block_start,
            )
        )

    for idx in range(body_start, len(lines)):
        ln = lines[idx]
        match = _FENCE_RE.match(ln)
        if fence:
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence) and not match.group(2):
                close_block()
                fence = ""
            else:
                block.append(ln)
            continue
        if match:
            fence = match.group(1)
            block = []
            block_start = idx + 1
            block_lang = match.group(2)
            continue
        for inline in _INLINE_EXEC_RE.finditer(ln):
            where = f"第 {idx + 1} 行"
            findings.append(Finding(REVIEW, CAT_HOOK, rel, where, f"技能載入時自動執行的行內指令：{inline.group(1)[:200]}"))
            findings += _to_findings(analyze_text(inline.group(1), comment="#"), rel, where=where)
        findings += _to_findings(analyze_mention(ln), rel, line_offset=idx)
    if fence:
        close_block()  # 沒關的圍欄一路算到檔尾
    # 指示句型不分 frontmatter、內文或程式碼區塊，整份都看（提示詞常放在圍欄裡）。
    findings += _to_findings(analyze_instructions(text, is_agent_file(rel)), rel)
    return findings


def _show_command(command: Any, args: Any) -> str:
    parts = [command] if isinstance(command, str) else list(command) if isinstance(command, list) else []
    if isinstance(args, list):
        parts += args
    return " ".join(str(p) for p in parts)


def scan_json_obj(rel: str, obj: Any, filename: str) -> list[Finding]:
    findings: list[Finding] = []

    def add(hits: Iterable[Hit], ptr: str) -> None:
        findings.extend(_to_findings(hits, rel, where=ptr or "/"))

    def walk(node: Any, ptr: str, exec_ctx: bool, ancestors: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            low = {str(k).lower(): v for k, v in node.items()}
            kind = low["type"].lower() if isinstance(low.get("type"), str) else ""
            command = low.get("command")
            in_hooks = "hooks" in ancestors
            in_mcp = "mcpservers" in ancestors or "mcp_servers" in ancestors
            if isinstance(command, (str, list)):
                shown = _show_command(command, low.get("args"))
                if kind == "command" or in_hooks:
                    findings.append(Finding(REVIEW, CAT_HOOK, rel, ptr or "/", f"command hook（審批之外自動執行）：{shown[:300]}"))
                elif in_mcp:
                    findings.append(Finding(REVIEW, CAT_MCP, rel, ptr or "/", f"MCP 伺服器啟動指令：{shown[:300]}"))
                add(analyze_text(shown), ptr)
            elif in_hooks and kind in HOOK_TYPES_OTHER:
                extra = low.get("url") or low.get("prompt") or low.get("tool") or ""
                findings.append(Finding(REVIEW, CAT_HOOK, rel, ptr or "/", f"{kind} hook（審批之外自動執行）：{str(extra)[:200]}"))
            elif in_mcp and isinstance(low.get("url"), str):
                findings.append(Finding(REVIEW, CAT_MCP, rel, ptr or "/", f"遠端 MCP 伺服器：{low['url'][:200]}"))
            for key, value in node.items():
                kl = str(key).lower()
                if isinstance(value, (str, bool)):
                    pair = (kl, str(value).lower())
                    if pair in FAIL_PAIRS:
                        findings.append(Finding(FAIL, CAT_BYPASS, rel, f"{ptr}/{key}", f"{key}: {value}（{FAIL_PAIRS[pair]}）"))
                    elif pair in REVIEW_PAIRS:
                        findings.append(Finding(REVIEW, CAT_BYPASS, rel, f"{ptr}/{key}", f"{key}: {value}（{REVIEW_PAIRS[pair]}）"))
                walk(value, f"{ptr}/{key}", exec_ctx or kl in JSON_EXEC_KEYS, ancestors + (kl,))
        elif isinstance(node, list):
            if exec_ctx and node and all(isinstance(item, str) for item in node):
                add(analyze_text(" ".join(node)), ptr)  # 字串陣列就是 argv
            for idx, item in enumerate(node):
                walk(item, f"{ptr}/{idx}", exec_ctx, ancestors)
        elif isinstance(node, str):
            add(analyze_text(node) if exec_ctx else analyze_mention(node), ptr)
            add(analyze_instructions(node, is_agent_file(rel)), ptr)

    walk(obj, "", False, ())

    if filename == "package.json" and isinstance(obj, dict) and isinstance(obj.get("scripts"), dict):
        scripts = obj["scripts"]
        for name in NPM_INSTALL_FAIL:
            if name in scripts:
                findings.append(Finding(FAIL, CAT_INSTALL, rel, f"/scripts/{name}", f"npm install 會自動執行 {name}：{str(scripts[name])[:200]}"))
        for name in NPM_INSTALL_REVIEW:
            if name in scripts:
                findings.append(Finding(REVIEW, CAT_INSTALL, rel, f"/scripts/{name}", f"在套件目錄內跑 npm install 會執行 {name}：{str(scripts[name])[:200]}"))
    # 同一個指令會從 command、args、合併後的 argv 各被分析一次；同檔同內容只留第一筆。
    seen: set[tuple[str, ...]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = (item.severity, item.category, item.detail) + ((item.where,) if item.category in (CAT_HOOK, CAT_MCP) else ())
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[Finding] = set()
    out: list[Finding] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def decode_bytes(data: bytes) -> str | None:
    """回傳文字；判定為二進位時回傳 None。"""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")  # 規則都是 ASCII，換編碼不影響比對


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_pack(pack: Path, max_bytes: int = DEFAULT_MAX_BYTES, acknowledged: Iterable[str] = ()) -> PackReport:
    """掃描一個技能包目錄。只讀檔，不執行、不連網。"""
    report = PackReport(pack=str(pack))
    acked = {a.lower() for a in acknowledged}
    if not pack.exists():
        report.errors.append("目錄不存在")
        return report
    if not pack.is_dir():
        report.errors.append("不是目錄（--pack 要給技能包的根目錄）")
        return report

    def unscanned(rel: str, reason: str, path: Path | None = None) -> None:
        sha = ""
        if path is not None:
            try:
                sha = _sha256(path)
            except OSError:
                sha = ""
        report.unscanned.append(Unscanned(rel, reason, sha, bool(sha) and sha in acked))

    def on_walk_error(err: OSError) -> None:
        report.errors.append(f"無法讀取目錄 {err.filename}：{err.strerror}")

    seen_files = 0
    for dirpath, dirnames, filenames in os.walk(pack, onerror=on_walk_error, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(pack)
        dirnames.sort()
        if here.name == ".git":
            # git 物件庫是壓縮過的二進位，逐檔列未掃描沒有意義；只掃會被 git 執行或讀取的部分。
            dirnames[:] = [d for d in dirnames if d == "hooks"]
            filenames = [f for f in filenames if f == "config"]
            report.notes.append(f"{rel_dir.as_posix()}：只掃 config 與 hooks/，物件庫與其餘中繼資料未掃描")
        for name in list(dirnames):
            if (here / name).is_symlink():
                dirnames.remove(name)
                seen_files += 1
                unscanned((rel_dir / name).as_posix(), "符號連結目錄，不跟隨")
        for name in sorted(filenames):
            path = here / name
            rel = (rel_dir / name).as_posix()
            seen_files += 1
            if path.is_symlink():
                unscanned(rel, "符號連結，不跟隨")
                continue
            try:
                size = path.stat().st_size
                if size > max_bytes:
                    unscanned(rel, f"超過大小上限（{size} > {max_bytes} bytes）", path)
                    continue
                data = path.read_bytes()
            except OSError as err:
                unscanned(rel, f"讀不到：{err.strerror or err}")
                continue
            text = decode_bytes(data)
            if text is None:
                unscanned(rel, "二進位檔", path)
                continue
            ext = path.suffix.lower()
            lower = name.lower()
            parts = [p.lower() for p in rel_dir.parts]
            if ext in MARKDOWN_EXT or (not ext and lower in PROSE_NAMES):
                report.findings += scan_markdown(rel, text)
            elif ext == ".json":
                try:
                    report.findings += scan_json_obj(rel, json.loads(text), lower)
                except (ValueError, RecursionError):
                    report.findings += scan_script(rel, text, ".jsonc")
                    unscanned(rel, "JSON 解析失敗，hooks／scripts 無法逐項列出（已改用純文字掃描）", path)
                    report.scanned.append(rel)
                    continue
            else:
                report.findings += scan_script(rel, text, ext)
            if ".git" in parts and "hooks" in parts and not lower.endswith(".sample"):
                report.findings.append(Finding(REVIEW, CAT_HOOK, rel, "整個檔案", "已啟用的 git hook，git 操作時自動執行"))
            if lower == "setup.py":
                report.findings.append(Finding(REVIEW, CAT_INSTALL, rel, "整個檔案", "setup.py 在 pip install 時執行"))
            if lower == "binding.gyp":
                report.findings.append(Finding(REVIEW, CAT_INSTALL, rel, "整個檔案", "有 binding.gyp 時 npm install 預設會跑 node-gyp rebuild"))
            report.scanned.append(rel)

    report.findings = _dedupe(report.findings)
    if seen_files == 0 and not report.errors:
        report.errors.append("目錄是空的，沒有任何檔案可掃描")
    elif not report.scanned and not report.errors:
        report.errors.append("沒有任何檔案被掃描")
    return report


# ---------------------------------------------------------------------------
# 宣告模式（補充）：檢查填寫者自述的 JSON。不讀任何第三方檔案。
# ---------------------------------------------------------------------------

BANNED_OVERCLAIMS = (
    "100% undetectable",
    "guaranteed viral",
    "auto-post unattended without approval",
)


def default_suite() -> dict[str, Any]:
    """內建的宣告範例：2026-11-08 盤點的五組開源 Agent Skill / MCP 工具鏈。內容是人工填寫，不是掃描結果。"""
    return {
        "packs": [
            {
                "id": "pbakaus/impeccable",
                "category": "ui-design-anti-slop",
                "cli_invocations": [
                    "npx impeccable detect src/",
                    "npx impeccable detect --json .",
                ],
                "env_overrides": {
                    "IMPECCABLE_LIVE_COPY_AGENT": "chat",
                    "DO_NOT_TRACK": "1",
                },
                "config": {
                    "telemetry": False,
                    "hook_reviewed": True,
                    "disable_hooks_flag": "--settings '{\"disableAllHooks\": true}'",
                },
                "human_publish_only": True,
                "unknown_metric_placeholder": "{{your number}}",
                "deterministic_tools": ["npx impeccable detect (62 deterministic rules)"],
                "claims": ["heuristic usability and anti-slop detector"],
            },
            {
                "id": "Jakeschincariol/instagram-agent-skill",
                "category": "social-content-workflow",
                "cli_invocations": [
                    "python3 skills/ig-reel/hookscore.py hooks.txt",
                    "python3 skills/ig-human/humanize.py draft.txt --report",
                    "python3 skills/ig-human/detect.py draft.txt",
                ],
                "env_overrides": {
                    "DO_NOT_TRACK": "1",
                },
                "config": {
                    "telemetry": False,
                    "hook_reviewed": True,
                    "disable_hooks_flag": "none-required",
                },
                "human_publish_only": True,
                "unknown_metric_placeholder": "{{your number}}",
                "deterministic_tools": [
                    "hookscore.py",
                    "beats.py",
                    "caption.py",
                    "humanize.py",
                    "detect.py",
                    "swipe.py",
                ],
                "claims": ["local heuristic 5-check panel, hookscore AUC 0.83 on bad hooks / 0.56 on winners"],
            },
            {
                "id": "Jakeschincariol/youtube-agent-skill",
                "category": "social-content-workflow",
                "cli_invocations": [
                    "python3 skills/yt-script/hookscore.py --hook 'example'",
                    "python3 skills/yt-package/title.py --title 'A' --thumb 'B'",
                    "python3 skills/yt-edit/deadair.py transcript.srt",
                ],
                "env_overrides": {
                    "DO_NOT_TRACK": "1",
                },
                "config": {
                    "telemetry": False,
                    "hook_reviewed": True,
                    "disable_hooks_flag": "none-required",
                },
                "human_publish_only": True,
                "unknown_metric_placeholder": "{{your number}}",
                "deterministic_tools": [
                    "hookscore.py",
                    "title.py",
                    "deadair.py",
                    "chapters.py",
                    "retention.py",
                    "swipe.py",
                ],
                "claims": ["heuristic hook panel calibrated on 74 hooks, draft-only"],
            },
            {
                "id": "Leonxlnx/earshot",
                "category": "multimedia-audio-verification",
                "cli_invocations": [
                    "earshot describe enter.ogg",
                    "earshot critique film.mp4",
                    "earshot timeline film.mp4",
                ],
                "env_overrides": {
                    "DO_NOT_TRACK": "1",
                },
                "config": {
                    "telemetry": False,
                    "hook_reviewed": True,
                    "disable_hooks_flag": "none-required",
                },
                "human_publish_only": True,
                "unknown_metric_placeholder": "{{your number}}",
                "deterministic_tools": [
                    "earshot measure (LUFS, true peak, LRA, spectrum)",
                    "earshot critique (23 scored metrics against reference profile)",
                ],
                "claims": ["CPU-only local audio measurement and reference comparison"],
            },
            {
                "id": "chaseai-yt/claudex-loop",
                "category": "cross-model-plan-and-review",
                "cli_invocations": [
                    "python scripts/validate.py",
                    "python -m unittest discover -s tests -v",
                ],
                "env_overrides": {
                    "DO_NOT_TRACK": "1",
                },
                "config": {
                    "telemetry": False,
                    "hook_reviewed": True,
                    "disable_hooks_flag": "read-only-review-sandbox",
                },
                "human_publish_only": True,
                "unknown_metric_placeholder": "{{your number}}",
                "deterministic_tools": [
                    "SHA256 plan approval fingerprint",
                    "read-only shell sandbox for reviews",
                ],
                "claims": ["four-phase cross-model review with SHA256 plan invalidation"],
            },
        ]
    }


def validate_suite(data: Any) -> list[str]:
    """檢查宣告 JSON。`[SKILLPACK-000]` 是結構錯誤（結束碼 2），其餘是規則違反（結束碼 1）。"""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["[SKILLPACK-000] 最外層必須是物件"]
    packs = data.get("packs")
    if not isinstance(packs, list) or not packs:
        return ["[SKILLPACK-000] 'packs' 必須為非空陣列"]

    for idx, pack in enumerate(packs):
        if not isinstance(pack, dict):
            errors.append(f"[SKILLPACK-000] packs[{idx}] 必須為物件")
            continue
        pid = str(pack.get("id") or f"pack#{idx}")

        # SKILLPACK-001: No-Bypass-Sandbox-Escalation（與目錄掃描共用同一套 argv 解析）
        invocations = pack.get("cli_invocations")
        if not isinstance(invocations, list) or not all(isinstance(c, str) for c in invocations):
            errors.append(f"[SKILLPACK-000] {pid}: cli_invocations 必須為字串陣列")
        else:
            for cmd in invocations:
                for hit in analyze_text(cmd):
                    if hit.severity != FAIL:
                        continue
                    if hit.category == CAT_BYPASS:
                        errors.append(f"[SKILLPACK-001] {pid}: 偵測到禁止的免審批／破沙盒旗標 {hit.detail} 於指令：{cmd}")
                    else:
                        errors.append(f"[SCAN-{hit.category}] {pid}: {hit.detail}")

        env_map = pack.get("env_overrides", {})
        if not isinstance(env_map, dict):
            errors.append(f"[SKILLPACK-000] {pid}: env_overrides 必須為物件")
        elif pid == "pbakaus/impeccable" and env_map.get("IMPECCABLE_LIVE_COPY_AGENT") not in ("chat", "off"):
            errors.append(
                f"[SKILLPACK-001] {pid}: 必須設定 IMPECCABLE_LIVE_COPY_AGENT 為 'chat' 或 'off'，"
                "以防止 Live Mode 逾時後自動以免審批模式喚起背景 CLI"
            )

        # SKILLPACK-002: Hook-And-Telemetry-Gate
        cfg = pack.get("config")
        if not isinstance(cfg, dict):
            errors.append(f"[SKILLPACK-000] {pid}: config 必須為物件")
        else:
            if cfg.get("telemetry") is not False:
                errors.append(f"[SKILLPACK-002] {pid}: config.telemetry 必須顯式設為 false")
            if cfg.get("hook_reviewed") is not True:
                errors.append(f"[SKILLPACK-002] {pid}: config.hook_reviewed 必須為 true（確認已審查背景 Hook）")
            if not str(cfg.get("disable_hooks_flag") or "").strip():
                errors.append(f"[SKILLPACK-002] {pid}: 必須記錄 disable_hooks_flag 緊急停用機制")

        # SKILLPACK-003: Zero-Fabrication-Placeholder & Human-Publish Gate
        if pack.get("human_publish_only") is not True:
            errors.append(f"[SKILLPACK-003] {pid}: human_publish_only 必須為 true（禁止未經人工確認自動發文或推送）")
        placeholder = str(pack.get("unknown_metric_placeholder") or "")
        if "{{" not in placeholder or "}}" not in placeholder:
            errors.append(
                f"[SKILLPACK-003] {pid}: unknown_metric_placeholder 必須使用顯式模板佔位符（如 '{{{{your number}}}}'），禁止捏造數據"
            )

        # SKILLPACK-004: Deterministic-Linter-Backing & Anti-Overclaim
        det_tools = pack.get("deterministic_tools", [])
        if not isinstance(det_tools, list) or not det_tools:
            errors.append(f"[SKILLPACK-004] {pid}: deterministic_tools 不可為空，必須附帶確定性本地檢驗工具")
        claims = pack.get("claims", [])
        if not isinstance(claims, list):
            errors.append(f"[SKILLPACK-000] {pid}: claims 必須為陣列")
        else:
            for c in claims:
                c_low = str(c).lower()
                for banned in BANNED_OVERCLAIMS:
                    if banned in c_low:
                        errors.append(f"[SKILLPACK-004] {pid}: 偵測到誇大不實宣稱 '{banned}' 於：{c}")

    return errors


DECLARATION_CAVEAT = "宣告模式只檢查填寫者自述的 JSON，沒有讀取任何第三方檔案，不能當作採納依據；採納前請用 --pack 掃描實際目錄。"
PASS_CAVEAT = "這是靜態啟發式掃描，通過不代表安全，仍需人工審查。"
NO_TARGET_MESSAGE = "沒有指定檢查對象，什麼都沒檢查。採納檢查請用 --pack <目錄>；宣告檢查用 --config <檔案>，內建範例自檢用 --self-test。"


def load_declaration(path: Path) -> tuple[Any, str]:
    """回傳 (資料, 錯誤訊息)。讀不到或不是合法 JSON 時資料為 None。"""
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), ""
    except OSError as err:
        return None, f"讀不到宣告檔 {path}：{err.strerror or err}"
    except ValueError as err:
        return None, f"宣告檔不是合法 JSON：{err}"


def compute_exit_code(reports: list[PackReport], declaration_errors: list[str], input_errors: list[str], strict: bool) -> int:
    found = any(r.fails() or (strict and r.reviews()) for r in reports)
    found = found or any(not e.startswith("[SKILLPACK-000]") for e in declaration_errors)
    if found:
        return 1
    incomplete = bool(input_errors) or any(r.errors or r.blocking_unscanned() for r in reports)
    incomplete = incomplete or any(e.startswith("[SKILLPACK-000]") for e in declaration_errors)
    return 2 if incomplete else 0


def _print_pack(report: PackReport, strict: bool) -> None:
    fails, reviews, blocking = report.fails(), report.reviews(), report.blocking_unscanned()
    if fails or (strict and reviews):
        status = "FAIL"
    elif report.errors or blocking:
        status = "INCOMPLETE"
    else:
        status = "PASS"
    print(
        f"[{status}] {report.pack}：已掃描 {len(report.scanned)} 個檔案，"
        f"FAIL {len(fails)} 項、需人工審查 {len(reviews)} 項、未掃描 {len(report.unscanned)} 個"
    )
    for err in report.errors:
        print(f"  ERROR     {err}")
    for item in fails + reviews:
        print(f"  {item.severity:<9} [{item.category}] {item.file}（{item.where}）— {item.detail}")
    for item in report.unscanned:
        tag = "已人工確認" if item.acknowledged else "未掃描"
        sha = f"，sha256={item.sha256}" if item.sha256 else ""
        print(f"  UNSCANNED {item.file} — {tag}：{item.reason}{sha}")
    for note in report.notes:
        print(f"  NOTE      {note}")


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    parser = argparse.ArgumentParser(
        description="第三方 Agent Skill／MCP 技能包的靜態啟發式掃描。結束碼：0 通過、1 發現問題、2 輸入錯誤或無法掃描。"
    )
    parser.add_argument("--pack", type=Path, action="append", default=[], help="要掃描的技能包目錄，可重複指定")
    declaration_source = parser.add_mutually_exclusive_group()
    declaration_source.add_argument("--config", type=Path, help="宣告 JSON（補充用，不讀第三方檔案）")
    declaration_source.add_argument("--self-test", action="store_true", help="只對內建的宣告範例做自檢（回 0 或 1）")
    parser.add_argument("--strict", action="store_true", help="把需人工審查（REVIEW）的項目也算成失敗")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="單檔大小上限，超過列為未掃描")
    parser.add_argument(
        "--ack-unscanned",
        action="append",
        default=[],
        metavar="SHA256",
        help="人工看過某個未掃描檔後，用它的 sha256 確認；內容一變就失效。可重複指定",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式輸出結果")
    args = parser.parse_args(argv)

    input_errors: list[str] = []
    reports = [scan_pack(p, args.max_bytes, args.ack_unscanned) for p in args.pack]

    declaration: Any = None
    declaration_errors: list[str] = []
    declaration_checked = False
    if args.config:
        declaration, problem = load_declaration(args.config)
        if problem:
            input_errors.append(problem)
        else:
            declaration_checked = True
    elif args.self_test:
        declaration = default_suite()
        declaration_checked = True
    elif not args.pack:
        input_errors.append(NO_TARGET_MESSAGE)  # 什麼都沒檢查，不能回 0
    if declaration_checked:
        declaration_errors = validate_suite(declaration)
    pack_count = len(declaration["packs"]) if isinstance(declaration, dict) and isinstance(declaration.get("packs"), list) else 0

    code = compute_exit_code(reports, declaration_errors, input_errors, args.strict)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": code == 0,
                    "exit_code": code,
                    "mode": "pack-scan" if reports else "self-test" if args.self_test else "declaration-only" if args.config else "none",
                    "adoption_evidence": bool(reports),
                    "caveat": PASS_CAVEAT if reports else DECLARATION_CAVEAT,
                    "strict": args.strict,
                    "packs": [r.as_dict() for r in reports],
                    "pack_count": pack_count,
                    "errors": declaration_errors,
                    "input_errors": input_errors,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return code

    for err in input_errors:
        print(f"[ERROR] {err}")
    for report in reports:
        _print_pack(report, args.strict)
    if declaration_checked:
        label = "內建宣告範例自檢" if args.self_test else "宣告檢查"
        if declaration_errors:
            print(f"[FAIL] {label}失敗：")
            for err in declaration_errors:
                print(f"  - {err}")
        else:
            print(f"[PASS] {label}通過（共 {pack_count} 組宣告）。")
        print(f"  注意：{DECLARATION_CAVEAT}")
    if reports:
        summary = {0: "[PASS] 掃描完整，沒有 FAIL。", 1: "[FAIL] 發現問題，見上方清單。", 2: "[INCOMPLETE] 無法完整掃描，不能視為通過。"}[code]
        print(f"{summary}{PASS_CAVEAT}")
    return code


if __name__ == "__main__":
    sys.exit(main())
