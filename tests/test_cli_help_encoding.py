"""每支 tools/*.py 的 --help 在 cp950 環境下都要輸出合法 UTF-8、結束碼 0、且沒有副作用。

Windows 管線預設用系統編碼（cp950）。工具若在 argparse 之後才把輸出改成 UTF-8，
--help 會在改之前就印出來，Agent 讀到的是亂碼；沒有 argparse 的工具甚至會把 --help 當成檔名。
「沒有副作用」：在空的暫存目錄執行（家目錄也指到暫存目錄），執行後該目錄仍是空的。
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
EXPECTED = {
    "audit_oauth_credentials.py",
    "screen_privacy.py",
    "verify_agent_skill_pack_safety.py",
    "verify_cloud_persistence_audit.py",
    "verify_tool_call_firewall.py",
}


class CliHelpEncodingTest(unittest.TestCase):
    def test_tool_set_is_the_documented_five(self):
        self.assertEqual({p.name for p in TOOLS.glob("*.py")}, EXPECTED)

    def test_every_tool_help_is_utf8_under_cp950_without_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            work = Path(tmp) / "work"
            home.mkdir()
            work.mkdir()
            env = {
                **os.environ,
                "PYTHONIOENCODING": "cp950",
                "PYTHONUTF8": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "HOME": str(home),
                "USERPROFILE": str(home),
            }
            for tool in sorted(TOOLS / n for n in EXPECTED):
                with self.subTest(tool=tool.name):
                    proc = subprocess.run(
                        [sys.executable, str(tool), "--help"],
                        capture_output=True, env=env, cwd=work, timeout=60,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace")[-300:])
                    text = proc.stdout.decode("utf-8")  # 不是 UTF-8 會在這裡丟 UnicodeDecodeError
                    self.assertIn("usage", text)
                    self.assertEqual(list(work.iterdir()), [], "--help 不得在工作目錄留下檔案")
                    self.assertEqual(list(home.iterdir()), [], "--help 不得在家目錄留下檔案")


if __name__ == "__main__":
    unittest.main()
