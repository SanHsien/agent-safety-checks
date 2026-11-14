"""以獨立行程守住 CLI 結束碼；不讀取實際使用者的設定。"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
OPTIONS = {
    "verify_agent_skill_pack_safety.py": ("--pack", "--config"),
    "verify_tool_call_firewall.py": ("--verify-calls", "--analyze-trace"),
    "verify_cloud_persistence_audit.py": (
        "--scan-dir", "--audit-accounts-json", "--audit-mcp-config",
    ),
    "audit_oauth_credentials.py": ("--home", "--dir", "--repo"),
    "screen_privacy.py": ("--title", "--ocr-file"),
}


class CliExitCodesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.home = self.work / "home"
        self.home.mkdir()
        self.env = dict(os.environ)
        for key in ("CODEX_HOME", "CLAUDE_CONFIG_DIR"):
            self.env.pop(key, None)
        self.env.update(
            HOME=str(self.home), USERPROFILE=str(self.home),
            TEMP=str(self.home), TMP=str(self.home),
            PYTHONDONTWRITEBYTECODE="1",
        )

    def run_cli(self, tool: str, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(TOOLS / tool), *args],
            cwd=self.work, env=self.env, capture_output=True, timeout=30,
        )

    def assert_code(self, tool: str, expected: int, *args: str) -> bytes:
        result = self.run_cli(tool, *args)
        self.assertEqual(
            result.returncode, expected,
            f"{tool} {args}: {result.stderr.decode('utf-8', 'replace')[-300:]}",
        )
        return result.stdout

    def write_json(self, name: str, data: object) -> str:
        path = self.work / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_bare_execution_rejects_missing_target_except_oauth_default_scan(self) -> None:
        for tool in OPTIONS:
            with self.subTest(tool=tool):
                # OAuth 預設稽核隔離家目錄；沒有憑證不等於參數缺漏。
                self.assert_code(tool, 0 if tool == "audit_oauth_credentials.py" else 2)

    def test_missing_option_value_is_input_error_for_every_tool(self) -> None:
        for tool, options in OPTIONS.items():
            for option in options:
                with self.subTest(tool=tool, option=option):
                    self.assert_code(tool, 2, option)

    def test_unknown_option_is_input_error_for_every_tool(self) -> None:
        for tool in OPTIONS:
            with self.subTest(tool=tool):
                self.assert_code(tool, 2, "--unknown-option")

    def test_missing_file_or_directory_is_input_error_not_a_rule_hit(self) -> None:
        missing = str(self.work / "missing")
        for tool, options in OPTIONS.items():
            for option in options:
                if option == "--title":
                    continue
                with self.subTest(tool=tool, option=option):
                    self.assert_code(tool, 2, option, missing)

    def test_directory_in_place_of_input_file_is_input_error(self) -> None:
        for tool, options in (
            ("verify_agent_skill_pack_safety.py", ("--config",)),
            ("verify_tool_call_firewall.py", OPTIONS["verify_tool_call_firewall.py"]),
            ("verify_cloud_persistence_audit.py", ("--audit-accounts-json", "--audit-mcp-config")),
            ("screen_privacy.py", ("--ocr-file",)),
        ):
            for option in options:
                with self.subTest(tool=tool, option=option):
                    self.assert_code(tool, 2, option, str(self.home))

    def test_file_in_place_of_scan_directory_is_input_error(self) -> None:
        path = self.write_json("file.json", {})
        for tool, options in (
            ("verify_agent_skill_pack_safety.py", ("--pack",)),
            ("verify_cloud_persistence_audit.py", ("--scan-dir",)),
            ("audit_oauth_credentials.py", OPTIONS["audit_oauth_credentials.py"]),
        ):
            for option in options:
                with self.subTest(tool=tool, option=option):
                    self.assert_code(tool, 2, option, path)

    def test_empty_or_malformed_json_is_input_error_not_a_rule_hit(self) -> None:
        path = self.work / "invalid.json"
        for content in ("", "{", "null"):
            path.write_text(content, encoding="utf-8")
            for tool, options in (
                ("verify_agent_skill_pack_safety.py", ("--config",)),
                ("verify_tool_call_firewall.py", OPTIONS["verify_tool_call_firewall.py"]),
                ("verify_cloud_persistence_audit.py", ("--audit-accounts-json", "--audit-mcp-config")),
            ):
                for option in options:
                    with self.subTest(tool=tool, option=option, content=content):
                        self.assert_code(tool, 2, option, str(path))

    def test_skill_pack_clean_passes_dangerous_flag_hits_and_empty_cannot_pass(self) -> None:
        pack = self.work / "pack"
        pack.mkdir()
        self.assert_code("verify_agent_skill_pack_safety.py", 2, "--pack", str(pack))
        skill = pack / "SKILL.md"
        skill.write_text("---\nname: sample\ndescription: Local notes\n---\nRead local notes.\n", encoding="utf-8")
        self.assert_code("verify_agent_skill_pack_safety.py", 0, "--pack", str(pack))
        skill.write_text("```bash\nclaude --dangerously-" + "skip-permissions\n```\n", encoding="utf-8")
        self.assert_code("verify_agent_skill_pack_safety.py", 1, "--pack", str(pack))

    def test_firewall_allowed_read_passes_and_unknown_tool_is_a_rule_hit(self) -> None:
        path = self.write_json("calls.json", {"invocations": [{"call": {
            "tool": "read_file", "role": "implementer", "path": "src/example.py",
        }}]})
        self.assert_code("verify_tool_call_firewall.py", 0, "--verify-calls", path)
        path = self.write_json("calls.json", {"invocations": [{"call": {"tool": "unknown"}}]})
        self.assert_code("verify_tool_call_firewall.py", 1, "--verify-calls", path)

    def test_valid_trace_passes_and_empty_span_list_is_input_error(self) -> None:
        path = self.write_json("trace.json", [{
            "span_id": "one", "start_ms": 0, "end_ms": 1, "total_tokens": 1,
        }])
        self.assert_code("verify_tool_call_firewall.py", 0, "--analyze-trace", path)
        path = self.write_json("trace.json", [])
        self.assert_code("verify_tool_call_firewall.py", 2, "--analyze-trace", path)

    def test_cloud_clean_scan_passes_and_known_artifact_is_a_rule_hit(self) -> None:
        self.assert_code("verify_cloud_persistence_audit.py", 0, "--scan-dir", str(self.home))
        (self.home / ".mainhelper").touch()
        self.assert_code("verify_cloud_persistence_audit.py", 1, "--scan-dir", str(self.home))

    def test_oauth_clean_config_passes_and_exposed_listener_is_a_rule_hit(self) -> None:
        config = self.home / ".codex"
        config.mkdir()
        path = config / "config.toml"
        path.write_text('listen = "127.0.0.1:8080"\n', encoding="utf-8")
        self.assert_code("audit_oauth_credentials.py", 0, "--home", str(self.home))
        path.write_text('listen = "0.0.0.0:8080"\n', encoding="utf-8")
        self.assert_code("audit_oauth_credentials.py", 1, "--home", str(self.home))

    def test_screen_allowed_and_blocked_titles_both_return_zero_with_classification(self) -> None:
        for title, classification in (("Notes", b"ok"), ("1Password", b"blocked")):
            with self.subTest(title=title):
                output = self.assert_code("screen_privacy.py", 0, "--title", title)
                self.assertIn(b"classification: " + classification, output)

    def test_screen_sensitive_ocr_returns_zero_but_requires_drop_image(self) -> None:
        path = self.work / "ocr.txt"
        path.write_text("ghp_" + "A" * 36, encoding="utf-8")
        output = self.assert_code("screen_privacy.py", 0, "--ocr-file", str(path))
        self.assertIn(b"action: drop_image", output)


if __name__ == "__main__":
    unittest.main()
