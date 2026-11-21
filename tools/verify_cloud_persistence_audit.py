#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Persistence & Stealer Artifacts Auditor (verify_cloud_persistence_audit.py)
---------------------------------------------------------------------------------
離線啟發式稽核，不判定感染或帳號授權是否合法。
--scan-dir 僅掃指定目錄檔名，不自動發現 LaunchAgents/Startup。
--scan-run-keys 唯讀 HKCU/HKLM Run/RunOnce 32/64-bit views；非 Windows 明示跳過。
帳號輸入須為非空陣列或 {"accounts": [...]}：email 唯一、roles 字串陣列，
has_user_managed_keys 選填 boolean（未提供視為 false，非遠端金鑰查證）。
createTime 為外部補入的含時區 ISO 8601 時間；缺漏不允許成功通過。
預設在任意 3600 秒（含邊界）內建立至少 5 個帳號即標記，可用 --burst-* 調整。
MCP 檢查 mcpServers/servers 的 headers/args/env 與 url 欄位（查詢參數、user:pass@）：
鍵名含 token/key/secret/password/credential 且值非佔位符即報出，另比對 ghp_、github_pat_、
sk-、sk-ant-、xox[abp]-、ya29.、AKIA 樣式；不作完整 MCP schema 驗證。
只豁免完整 ${VAR}/$VAR/%VAR%/{{VAR}}/<VAR>，不執行替換或 shell。
結束碼：0=所選檢查未命中；1=規則命中；2=輸入/讀取失敗或只跳過。
來源：
https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
https://docs.python.org/3/library/winreg.html
https://docs.cloud.google.com/iam/docs/roles-overview
IAM v1 ServiceAccount 不含 createTime；本地增補欄位，不宣稱可直接偵測原生匯出：
https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
"""

import os
import re
import sys
import json
import argparse
from urllib.parse import parse_qsl, urlsplit
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# 確保在 Windows CP950 等環境下輸出為 UTF-8（通過 test_cli_help_encoding 契約）
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


KNOWN_STEALER_ARTIFACTS = {
    "com.finder.helper.plist": "AMOS 木馬常用持久化 LaunchDaemon 設定檔",
    ".mainhelper": "AMOS 木馬憑證竊取後門元件",
    ".agent": "偽裝成 AI Agent 之惡意常駐腳本",
    ".pass": "明文或弱加密暫存憑證檔",
    ".id": "遭竊設備識別指紋檔"
}


def audit_local_persistence_artifacts(scan_dir: str) -> Tuple[bool, List[Dict[str, str]]]:
    """只掃指定目錄的已知檔名；無效或不可讀輸入不得通過。"""
    if not scan_dir or not os.path.isdir(scan_dir):
        raise ValueError("掃描目錄不存在或不是目錄，未掃描")
    findings = []

    def fail_walk(error):
        raise error

    # 目錄連結（符號連結、junction）也要走進去；用實際路徑去重，連結繞回自己時不會無限循環。
    visited = {os.path.realpath(scan_dir)}
    for root, dirs, files in os.walk(scan_dir, onerror=fail_walk, followlinks=True):
        kept = []
        for d in dirs:
            real = os.path.realpath(os.path.join(root, d))
            if real not in visited:
                visited.add(real)
                kept.append(d)
        dirs[:] = kept
        for fname in files:
            if fname.lower() in KNOWN_STEALER_ARTIFACTS:
                findings.append({
                    "file_path": os.path.join(root, fname),
                    "file_name": fname,
                    "threat_description": KNOWN_STEALER_ARTIFACTS[fname.lower()],
                })
    return not findings, findings


def audit_windows_run_keys():
    """唯讀 HKCU/HKLM Run/RunOnce 的 32/64-bit views；非 Windows 回 None。"""
    if sys.platform != "win32":
        print("[SKIP] 非 Windows，未檢查 Windows Run Keys")
        return None, []
    import winreg

    findings = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for name in ("Run", "RunOnce"):
            key_path = rf"Software\Microsoft\Windows\CurrentVersion\{name}"
            for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view)
                except FileNotFoundError:
                    continue
                with key:
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(count):
                        value_name, value, kind = winreg.EnumValue(key, index)
                        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value, str):
                            raise ValueError("Run Key 值不是可檢查的命令字串")
                        if any(marker in (value_name + " " + value).lower()
                               for marker in KNOWN_STEALER_ARTIFACTS):
                            # 不輸出命令內容，避免憑證外洩。
                            findings.append({"key": key_path, "view": view,
                                             "reason": "Run Key 含已知可疑檔名"})
    return not findings, findings


HIGH_PRIVILEGE_ROLES = {"roles/owner", "roles/editor", "roles/admin"}
# 角色名稱含這些字樣即視為高權限：管理類、AI 服務，以及可冒用其他帳號身分的角色。
HIGH_PRIVILEGE_ROLE_PARTS = ("admin", "vertex", "aiplatform", "tokencreator", "serviceaccountuser",
                             "workloadidentityuser")


def audit_service_account_anomalies(accounts, *, burst_window_seconds=3600, burst_threshold=5):
    """離線清單；任意滑動時間窗內 >= threshold 個不同 email 建立即標記。"""
    if not isinstance(accounts, list) or not accounts:
        raise ValueError("accounts 必須為非空陣列")
    if burst_window_seconds <= 0 or burst_threshold < 2:
        raise ValueError("時間窗須 > 0、激增門檻須 >= 2")
    anomalies = []
    timestamps = []
    seen = set()
    for acc in accounts:
        if not isinstance(acc, dict):
            raise ValueError("account 必須為物件")
        email, roles = acc.get("email"), acc.get("roles")
        if not isinstance(email, str) or not email.strip() or email in seen:
            raise ValueError("email 必須為非空且唯一字串")
        seen.add(email)
        if not isinstance(roles, list) or any(not isinstance(r, str) or not r for r in roles):
            raise ValueError("roles 必須為字串陣列，不能省略")
        has_keys = acc.get("has_user_managed_keys", False)
        if not isinstance(has_keys, bool):
            raise ValueError("has_user_managed_keys 必須為 boolean")
        if "createTime" in acc:
            raw = acc["createTime"]
            if not isinstance(raw, str):
                raise ValueError("createTime 必須為含時區 ISO 8601 字串")
            created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if created.tzinfo is None:
                raise ValueError("createTime 缺少時區")
            timestamps.append((created.timestamp(), email))
        default = email.endswith(("-compute@developer.gserviceaccount.com", "@appspot.gserviceaccount.com"))
        reasons = []
        if has_keys:
            reasons.append("具有使用者管理 Private Key（需人工確認用途與來源）")
        high_role = any(r.strip().lower() in HIGH_PRIVILEGE_ROLES or
                        any(part in r.lower() for part in HIGH_PRIVILEGE_ROLE_PARTS)
                        for r in roles)
        if not default and high_role:
            reasons.append("非預設帳號具高權限或 AI 角色")
        if reasons:
            anomalies.append({"email": email, "reasons": reasons,
                              "severity": "HIGH" if has_keys and not default else "MEDIUM"})
    timestamps.sort()
    left = 0
    flagged_upto = 0  # timestamps[:flagged_upto] 已併入 burst_emails；每筆只加一次，整體線性時間
    burst_emails = set()
    for right, (stamp, email) in enumerate(timestamps):
        while stamp - timestamps[left][0] > burst_window_seconds:
            left += 1
        if right - left + 1 >= burst_threshold:
            burst_emails.update(item[1] for item in timestamps[max(left, flagged_upto):right + 1])
            flagged_upto = right + 1
    if burst_emails:
        anomalies.append({"email": "(creation burst)", "severity": "HIGH",
                          "reasons": [f"{burst_window_seconds} 秒窗內至少 {burst_threshold} 個帳號建立；共標記 {len(burst_emails)} 個"]})
    if len(timestamps) != len(accounts) and not anomalies:
        raise ValueError("缺 createTime，激增檢查不完整，不能通過")
    return not anomalies, anomalies


_ENV_PLACEHOLDER_RE = re.compile(
    r"^(\$\{[A-Za-z0-9_]+\}|\$[A-Za-z0-9_]+|%[A-Za-z0-9_]+%|\{\{[^}]+\}\}|<[^>]+>)$"
)
_BEARER_VALUE_RE = re.compile(r"(?i)\bBearer\s+([^\s\"']+)")


# 已知 token 樣式：任何 env/headers/args/url 值只要「含有」即報出（整值為佔位符者除外）。
_KNOWN_TOKEN_PATTERNS = [
    (re.compile(r"ghp_[0-9A-Za-z]{10,}"), "GitHub PAT (ghp_)"),
    (re.compile(r"(?<![0-9A-Za-z])gh[osur]_[0-9A-Za-z]{20,}"), "GitHub OAuth/App token (gho_/ghs_/ghu_/ghr_)"),
    (re.compile(r"(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}"), "Google API key (AIza)"),
    (re.compile(r"(?<![0-9A-Z])ASIA[0-9A-Z]{16}(?![0-9A-Z])"), "AWS temporary access key ID (ASIA)"),
    (re.compile(r"(?<![0-9A-Za-z])glpat-[0-9A-Za-z_-]{20,}"), "GitLab PAT (glpat-)"),
    (re.compile(r"(?<![0-9A-Za-z])hf_[0-9A-Za-z]{30,}"), "Hugging Face token (hf_)"),
    (re.compile(r"(?<![0-9A-Za-z])npm_[0-9A-Za-z]{36}"), "npm token (npm_)"),
    (re.compile(r"(?<![0-9A-Za-z])(?:xox[rs]|xapp)-[0-9A-Za-z-]{8,}"), "Slack token (xoxr-/xoxs-/xapp-)"),
    (re.compile(r"(?<![0-9A-Za-z])[sr]k_live_[0-9A-Za-z]{16,}"), "Stripe live key (sk_live_/rk_live_)"),
    (re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"), "Private key block"),
    (re.compile(r"github_pat_[0-9A-Za-z_]{10,}"), "GitHub fine-grained PAT"),
    (re.compile(r"(?<![0-9A-Za-z])sk-ant-[0-9A-Za-z_-]{8,}"), "Anthropic API key (sk-ant-)"),
    (re.compile(r"(?<![0-9A-Za-z])sk-[0-9A-Za-z_-]{16,}"), "OpenAI-style secret key (sk-)"),
    (re.compile(r"xox[abp]-[0-9A-Za-z-]{8,}"), "Slack token (xox[abp]-)"),
    (re.compile(r"ya29\.[0-9A-Za-z_.-]+"), "Google OAuth access token (ya29.)"),
    (re.compile(r"(?<![0-9A-Z])AKIA[0-9A-Z]{16}(?![0-9A-Z])"), "AWS access key ID (AKIA)"),
]
# 鍵名含這些字樣且值不是佔位符 -> 一律報出（不回顯值）。
_SENSITIVE_NAME_RE = re.compile(r"token|key|secret|password|passwd|credential", re.IGNORECASE)
# 只用在 headers 的鍵名：Cookie 標頭帶的是登入 session。
_SENSITIVE_HEADER_RE = re.compile(r"cookie", re.IGNORECASE)
# 只能代入環境變數的佔位符（${VAR}、$VAR、%VAR%）；<…>、{{…}} 裡若是已知 token 樣式仍要報。
_ENV_REF_RE = re.compile(r"^(\$\{[A-Za-z0-9_]+\}|\$[A-Za-z0-9_]+|%[A-Za-z0-9_]+%)$")
# 巢狀物件與其他欄位：鍵名含敏感字樣、但以這些字結尾的是設定（tokenUrl、keyFile…），不是憑證本身。
_NON_SECRET_SUFFIX_RE = re.compile(r"(?i)(?:url|uri|endpoint|path|file|dir|type|name|id|env|header|helper|"
                                   r"command|scopes?|mode|method|format|length|count|limit|timeout)$")
# 命令列旗標：以 - 或 _ 分段後有一段是這些字，就是帶憑證的旗標（--api-key、--client-secret、--token=…）。
_SENSITIVE_FLAG_PARTS = frozenset({"token", "key", "apikey", "secret", "password", "passwd", "pwd",
                                   "credential", "credentials", "pat", "auth"})
_NON_SECRET_FLAG_PARTS = frozenset({"file", "path", "dir", "env", "name", "id", "url", "type", "header",
                                    "helper", "command", "max", "min", "limit", "count", "length", "layout",
                                    "mode", "method", "format", "timeout", "board", "tokens"})
_FLAG_RE = re.compile(r"^--?([A-Za-z][A-Za-z0-9_-]*)(?:=(.*))?$", re.DOTALL)
_URL_USERINFO_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s]*:[^/?#@\s]+@")
_URL_FIELDS = ("url", "serverUrl", "httpUrl", "sseUrl")


def _scan_value_patterns(value: str) -> List[str]:
    """回傳值內命中的已知 token 樣式說明；整值為環境變數參照者不報（<…>、{{…}} 包住的真 token 照報）。"""
    if _ENV_REF_RE.fullmatch(value.strip()):
        return []
    return [desc for pattern, desc in _KNOWN_TOKEN_PATTERNS if pattern.search(value)]


def _is_hardcoded_token(token_val: str) -> bool:
    return not bool(_ENV_PLACEHOLDER_RE.fullmatch(token_val.strip()))


def _is_sensitive_flag(name: str) -> bool:
    parts = [p for p in re.split(r"[-_]", name.lower()) if p]
    return (any(p in _SENSITIVE_FLAG_PARTS for p in parts)
            and not any(p in _NON_SECRET_FLAG_PARTS for p in parts))


def _flag_value_reasons(tokens: List[str], group: str) -> List[str]:
    """命令列 `--api-key 值`、`--token=值`：旗標名稱帶憑證字樣、值不是佔位符就報（不回顯值）。"""
    reasons = []
    for i, tok in enumerate(tokens):
        m = _FLAG_RE.match(tok.strip().strip("\"'"))
        if not m or not _is_sensitive_flag(m.group(1)):
            continue
        value = m.group(2)
        if value is None:
            nxt = tokens[i + 1].strip() if i + 1 < len(tokens) else ""
            value = "" if nxt.startswith("-") else nxt
        value = value.strip().strip("\"'")
        if value and _is_hardcoded_token(value):
            reasons.append(f"{group} 的憑證旗標帶寫死的值")
    return reasons


def _walk_strings(node: Any, key: str = "", depth: int = 0):
    """產生巢狀物件裡每個字串值與它所屬的鍵名（陣列元素沿用上層鍵名）。"""
    if depth > 64:
        raise ValueError("MCP 設定巢狀層數過深")
    if isinstance(node, str):
        yield key, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, str(k), depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_strings(v, key, depth + 1)


def _collect_server_maps(config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """根層 mcpServers／servers、VS Code 的 mcp.servers，以及任何深度的 mcpServers
    （例如 Claude Code ~/.claude.json 的 projects.<路徑>.mcpServers；空的巢狀 map 不算錯）。"""
    top = [config_data[k] for k in ("mcpServers", "servers") if k in config_data]
    if any(not isinstance(m, dict) for m in top):
        raise ValueError("mcpServers/servers 必須為非空物件")
    maps: List[Any] = list(top)
    mcp = config_data.get("mcp")
    nested: List[Any] = []
    if isinstance(mcp, dict):
        nested.extend(mcp[k] for k in ("mcpServers", "servers") if k in mcp)

    def walk(node: Any, depth: int) -> None:
        if depth > 64:
            raise ValueError("MCP 設定巢狀層數過深")
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "mcpServers" and node is not config_data and node is not mcp:
                    nested.append(v)
                walk(v, depth + 1)
        elif isinstance(node, list):
            for v in node:
                walk(v, depth + 1)

    walk(config_data, 0)
    if any(not isinstance(m, dict) for m in nested):
        raise ValueError("巢狀 mcpServers/servers 必須為物件")
    nested = [m for m in nested if m]
    # 根層的空 map 只有在巢狀位置另有 server 時才接受（~/.claude.json 常見根層空、projects 內有設定）
    if any(not m for m in top) and not nested:
        raise ValueError("mcpServers/servers 必須為非空物件")
    maps = [m for m in maps if m] + nested
    if not maps:
        raise ValueError("找不到任何 MCP server 設定")
    return maps


def audit_mcp_config_credentials(config_data):
    """嚴格檢查各種 server map；每個 server 的 headers/args/env/url/command 與其他欄位（含巢狀物件）都檢查。"""
    if not isinstance(config_data, dict):
        raise ValueError("MCP 根節點必須為物件")
    maps = _collect_server_maps(config_data)
    anomalies = []
    for servers in maps:
        for srv_name, cfg in servers.items():
            if not isinstance(cfg, dict) or not cfg:
                raise ValueError("server 設定必須為物件")
            fields = []
            for group in ("headers", "env"):
                mapping = cfg.get(group, {})
                if not isinstance(mapping, dict) or any(not isinstance(v, str) for v in mapping.values()):
                    raise ValueError(f"{group} 必須為字串值物件")
                fields.extend((group, k, v) for k, v in mapping.items())
            args = cfg.get("args", [])
            if not isinstance(args, list) or any(not isinstance(v, str) for v in args):
                raise ValueError("args 必須為字串陣列")
            fields.extend(("args", str(i), v) for i, v in enumerate(args))
            reasons = []
            command = cfg.get("command", "")
            if not isinstance(command, str):
                raise ValueError("command 必須為字串")
            if command:
                fields.append(("command", "command", command))
            reasons.extend(_flag_value_reasons(args, "args"))
            reasons.extend(_flag_value_reasons(command.split(), "command"))
            # 其他欄位（cwd、oauth、auth…）：任何字串都比對已知 token 樣式；巢狀物件的敏感鍵名要是佔位符
            for field, value in cfg.items():
                if field in ("headers", "env", "args", "command") or field in _URL_FIELDS:
                    continue
                for key, text in _walk_strings(value, str(field)):
                    for desc in _scan_value_patterns(text):
                        reasons.append(f"{field} 含已知 token 樣式：{desc}")
                    if (isinstance(value, dict) and key != field and _SENSITIVE_NAME_RE.search(key)
                            and not _NON_SECRET_SUFFIX_RE.search(key) and text.strip()
                            and _is_hardcoded_token(text)):
                        reasons.append(f"{field} 內的敏感鍵名值非佔位符（寫死憑證）")
            for url_field in _URL_FIELDS:
                if url_field not in cfg:
                    continue
                url = cfg[url_field]
                if not isinstance(url, str):
                    raise ValueError(f"{url_field} 必須為字串")
                if _URL_USERINFO_RE.match(url) and not _ENV_PLACEHOLDER_RE.fullmatch(
                        url.split("@", 1)[0].rsplit(":", 1)[-1]):
                    reasons.append(f"{url_field} 含內嵌帳密 (user:pass@)")
                for desc in _scan_value_patterns(url):
                    reasons.append(f"{url_field} 含已知 token 樣式：{desc}")
                for qkey, qval in parse_qsl(urlsplit(url).query, keep_blank_values=True):
                    if (_SENSITIVE_NAME_RE.search(qkey) and qval.strip()
                            and _is_hardcoded_token(qval)):
                        reasons.append(f"{url_field} 查詢參數 '{qkey}' 寫死敏感值")
            for group, key, value in fields:
                if ((group in ("headers", "env") and _SENSITIVE_NAME_RE.search(key)
                        or group == "headers" and _SENSITIVE_HEADER_RE.search(key)) and value.strip()):
                    plain = re.sub(r"(?i)^(?:Bearer|Basic|Token)\s+", "", value.strip())
                    if _is_hardcoded_token(plain):
                        reasons.append(f"{group} '{key}' 為敏感鍵名且值非佔位符（寫死憑證）")
                for desc in _scan_value_patterns(value):
                    reasons.append(f"{group} 含已知 token 樣式：{desc}")
                if group == "headers" and key.lower() == "authorization":
                    token = re.sub(r"(?i)^Bearer\s+", "", value.strip())
                    if _is_hardcoded_token(token):
                        reasons.append("headers Authorization 寫死靜態憑證 / Bearer Token")
                for match in _BEARER_VALUE_RE.finditer(value):
                    if _is_hardcoded_token(match.group(1)):
                        reasons.append(f"{group} 含靜態 Bearer Token")
                # 命令列也可能使用 Basic 或自訂 Authorization scheme。
                if group in ("args", "command") and re.search(r"(?i)authorization\s*:", value):
                    token = re.split(r"(?i)authorization\s*:\s*", value, maxsplit=1)[1]
                    token = re.sub(r"(?i)^Bearer\s+", "", token.strip())
                    if _is_hardcoded_token(token):
                        reasons.append(f"{group} 含靜態 Authorization")
                if "ya29." in value and not _ENV_PLACEHOLDER_RE.fullmatch(value.strip()):
                    reasons.append(f"{group} 含靜態 ya29. Token")
                if "cloud-platform" in value:
                    reasons.append(f"{group} 含 cloud-platform scope，需人工審查最小權限")
            if reasons:
                reasons = list(dict.fromkeys(reasons))
                anomalies.append({"server": srv_name, "reasons": reasons, "severity": "HIGH"})
    return not anomalies, anomalies


def _reject_duplicate_keys(pairs):
    """同一物件出現重複鍵就拒絕：取第一個值的解析器會看到本工具沒檢查到的值，憑證仍躺在檔案裡。"""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("JSON 物件含重複鍵")
        out[key] = value
    return out


def _load_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=_reject_duplicate_keys)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="離線持久化與憑證規則稽核；0=所選檢查未命中，1=規則命中，2=輸入/讀取失敗或僅跳過")
    parser.add_argument("--scan-dir", help="只掃指定目錄的已知檔名（含 Startup 或 LaunchAgents）")
    parser.add_argument("--scan-run-keys", action="store_true", help="唯讀 Windows Run/RunOnce；非 Windows 明示跳過")
    parser.add_argument("--audit-accounts-json", help="離線帳號 JSON 陣列或 accounts 物件")
    parser.add_argument("--burst-window-seconds", type=int, default=3600)
    parser.add_argument("--burst-threshold", type=int, default=5)
    parser.add_argument("--audit-mcp-config", help="MCP JSON headers/args/env 檢查")
    args = parser.parse_args()
    selected = args.scan_dir or args.scan_run_keys or args.audit_accounts_json or args.audit_mcp_config
    if not selected:
        parser.error("至少選擇一項稽核")
    exit_code = 0
    completed = 0
    try:
        if args.scan_dir:
            safe, findings = audit_local_persistence_artifacts(args.scan_dir)
            completed += 1
            print(f"[{'PASS' if safe else 'ALERT'}] 指定目錄已知檔名檢查：{len(findings)} 筆命中")
            exit_code |= int(not safe)
        if args.scan_run_keys:
            safe, findings = audit_windows_run_keys()
            if safe is not None:
                completed += 1
                print(f"[{'PASS' if safe else 'ALERT'}] Run Keys 已知檔名檢查：{len(findings)} 筆命中")
                exit_code |= int(not safe)
        if args.audit_accounts_json:
            data = _load_json(args.audit_accounts_json)
            accounts = data.get("accounts") if isinstance(data, dict) else data
            safe, findings = audit_service_account_anomalies(
                accounts, burst_window_seconds=args.burst_window_seconds, burst_threshold=args.burst_threshold)
            completed += 1
            print(f"[{'PASS' if safe else 'ALERT'}] 帳號規則檢查：{len(findings)} 筆命中")
            exit_code |= int(not safe)
        if args.audit_mcp_config:
            data = _load_json(args.audit_mcp_config)
            safe, findings = audit_mcp_config_credentials(data)
            completed += 1
            print(f"[{'PASS' if safe else 'ALERT'}] MCP 規則檢查：{len(findings)} 筆命中")
            exit_code |= int(not safe)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        # 不回顯原始輸入或解析片段，以免錯誤訊息洩漏 Token。
        print(f"[ERROR] 輸入或讀取失敗，稽核未完成（{type(exc).__name__}）", file=sys.stderr)
        return 2
    return exit_code if completed else 2


if __name__ == "__main__":
    sys.exit(main())
