#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
單元測試：test_verify_cloud_persistence_audit.py
驗證 AMOS 竊密木馬特徵掃描與雲端 Service Account 異常稽核工具
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

# 將 tools 加入 sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))
import verify_cloud_persistence_audit as auditor

from verify_cloud_persistence_audit import (
    audit_local_persistence_artifacts,
    audit_service_account_anomalies,
    audit_mcp_config_credentials,
)


class TestVerifyCloudPersistenceAudit(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_clean_directory_scan(self):
        # 建立一般正常檔案
        normal_file = os.path.join(self.test_dir, "normal_script.py")
        with open(normal_file, "w", encoding="utf-8") as f:
            f.write("print('hello world')\n")

        is_clean, findings = audit_local_persistence_artifacts(self.test_dir)
        self.assertTrue(is_clean)
        self.assertEqual(len(findings), 0)

    def test_detect_amos_launch_daemon(self):
        # 建立模擬的 com.finder.helper.plist
        plist_path = os.path.join(self.test_dir, "com.finder.helper.plist")
        with open(plist_path, "w", encoding="utf-8") as f:
            f.write("<plist>malicious</plist>\n")

        is_clean, findings = audit_local_persistence_artifacts(self.test_dir)
        self.assertFalse(is_clean)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file_name"], "com.finder.helper.plist")

    def test_detect_hidden_mainhelper(self):
        # 建立隱藏的 .mainhelper
        helper_path = os.path.join(self.test_dir, ".mainhelper")
        with open(helper_path, "w", encoding="utf-8") as f:
            f.write("binary_payload")

        is_clean, findings = audit_local_persistence_artifacts(self.test_dir)
        self.assertFalse(is_clean)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file_name"], ".mainhelper")

    def test_service_account_default_safe(self):
        accounts = [
            {
                "email": "123456789-compute@developer.gserviceaccount.com",
                "createTime": "2026-11-14T00:00:00Z",
                "has_user_managed_keys": False,
                "roles": ["roles/editor"]
            }
        ]
        is_safe, anomalies = audit_service_account_anomalies(accounts)
        self.assertTrue(is_safe)
        self.assertEqual(len(anomalies), 0)

    def test_service_account_high_risk_private_key(self):
        accounts = [
            {
                "email": "backup-worker@my-project.iam.gserviceaccount.com",
                "has_user_managed_keys": True,
                "roles": ["roles/aiplatform.user", "roles/vertexai.admin"]
            }
        ]
        is_safe, anomalies = audit_service_account_anomalies(accounts)
        self.assertFalse(is_safe)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["severity"], "HIGH")
        self.assertEqual(len(anomalies[0]["reasons"]), 2)

    def test_service_account_medium_risk_roles(self):
        accounts = [
            {
                "email": "ai-caller@my-project.iam.gserviceaccount.com",
                "has_user_managed_keys": False,
                "roles": ["roles/aiplatform.user"]
            }
        ]
        is_safe, anomalies = audit_service_account_anomalies(accounts)
        self.assertFalse(is_safe)
        self.assertEqual(anomalies[0]["severity"], "MEDIUM")

    def test_mcp_config_detects_hardcoded_bearer_and_cloud_platform_scope(self):
        bad_cfg = {
            "mcpServers": {
                "gemini-notebook": {
                    "url": "https://notebook.googleapis.com/mcp",
                    "headers": {
                        "Authorization": "Bearer ya29.a0AfH6SMBxExampleHardcodedToken123456"
                    },
                    "args": [
                        "--scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/notebook"
                    ],
                }
            }
        }
        is_safe, anomalies = audit_mcp_config_credentials(bad_cfg)
        self.assertFalse(is_safe)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["server"], "gemini-notebook")
        self.assertEqual(anomalies[0]["severity"], "HIGH")
        self.assertTrue(any("Bearer Token" in r for r in anomalies[0]["reasons"]))
        self.assertTrue(any("cloud-platform" in r for r in anomalies[0]["reasons"]))

    def test_mcp_config_allows_env_placeholder(self):
        safe_cfg = {
            "mcpServers": {
                "gemini-notebook": {
                    "url": "https://notebook.googleapis.com/mcp",
                    "headers": {
                        "Authorization": "Bearer ${NOTEBOOK_ACCESS_TOKEN}"
                    },
                }
            }
        }
        is_safe, anomalies = audit_mcp_config_credentials(safe_cfg)
        self.assertTrue(is_safe, anomalies)
        self.assertEqual(anomalies, [])


class CloudAuditRegressions(unittest.TestCase):
    def test_owner_editor_admin_roles(self):
        for role in ('roles/owner', 'roles/editor', 'roles/admin', 'roles/iam.serviceAccountAdmin'):
            with self.subTest(role=role):
                self.assertFalse(audit_service_account_anomalies([
                    {'email': 'evil@p.iam.gserviceaccount.com', 'roles': [role],
                     'createTime': '2026-11-14T00:00:00Z'}])[0])

    def test_account_burst_sliding_window(self):
        rows = [{'email': f'new-{i}@p.iam.gserviceaccount.com', 'roles': [],
                 'createTime': '2026-11-14T00:00:00Z'} for i in range(100)]
        self.assertFalse(audit_service_account_anomalies(rows)[0])
        self.assertTrue(audit_service_account_anomalies(rows[:4])[0])
        spread = [dict(row, createTime=f'2026-11-{i+1:02}T00:00:00+00:00')
                  for i, row in enumerate(rows[:6])]
        self.assertTrue(audit_service_account_anomalies(spread)[0])
        with self.assertRaises(ValueError):
            audit_service_account_anomalies([dict(rows[0], createTime='bad')])

    def test_account_schema_fail_closed(self):
        for rows in ([], {}, [None], [{}], [{'email': 'x', 'roles': 'roles/owner'}],
                     [{'email': 'x', 'roles': [], 'has_user_managed_keys': 'false'}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                audit_service_account_anomalies(rows)

    def test_missing_creation_time_cannot_pass(self):
        with self.assertRaises(ValueError):
            audit_service_account_anomalies([{'email': 'x', 'roles': []}])

    def test_burst_threshold_and_window_edges(self):
        rows = [{'email': str(i), 'roles': [], 'createTime': '2026-11-14T00:00:00Z'}
                for i in range(4)]
        rows.append({'email': 'last', 'roles': [], 'createTime': '2026-11-14T01:00:00Z'})
        self.assertFalse(audit_service_account_anomalies(rows)[0])
        rows[-1]['createTime'] = '2026-11-14T01:00:01Z'
        self.assertTrue(audit_service_account_anomalies(rows)[0])
        self.assertFalse(audit_service_account_anomalies(rows, burst_threshold=4)[0])
        rows[-1]['createTime'] = '2026-11-14T02:00:00+01:00'
        self.assertFalse(audit_service_account_anomalies(rows)[0])
        for kwargs in ({'burst_threshold': 1}, {'burst_window_seconds': 0}):
            with self.assertRaises(ValueError):
                audit_service_account_anomalies(rows, **kwargs)

    def test_short_and_non_bearer_authorization(self):
        for value in ('Bearer abc123', 'Basic abc', 'abc', 'Bearer $(cmd)', 'Bearer `cmd`', ''):
            with self.subTest(value=value):
                self.assertFalse(audit_mcp_config_credentials(
                    {'mcpServers': {'x': {'headers': {'authorization': value}}}})[0])

    def test_placeholder_and_token_length_boundaries(self):
        for value in ('${TOKEN}', '$TOKEN', '%TOKEN%', '{{TOKEN}}', '<TOKEN>'):
            self.assertTrue(audit_mcp_config_credentials(
                {'servers': {'x': {'headers': {'Authorization': 'Bearer ' + value}}}})[0])
        for value in ('a', 'abc123', 'a' * 16):
            self.assertFalse(audit_mcp_config_credentials(
                {'servers': {'x': {'args': ['Bearer ' + value]}}})[0])

    def test_args_env_scan_each_token_field(self):
        for cfg in ({'args': ['--access-token', 'ya29.synthetic-review-only']},
                    {'env': {'X': 'prefix ya29.synthetic-review-only'}},
                    {'args': ['--header', 'Authorization: Basic abc']},
                    {'env': {'X': 'Bearer abc'}},
                    {'env': {'SCOPES': 'cloud-platform'}}):
            with self.subTest(cfg=cfg):
                self.assertFalse(audit_mcp_config_credentials({'mcpServers': {'x': cfg}})[0])

    def test_mcp_schema_fail_closed(self):
        for cfg in (None, [], {}, {'mcpServers': []}, {'mcpServers': {}}, {'servers': {'x': {}}},
                    {'servers': {'x': []}}, {'servers': {'x': {'args': 'bad'}}},
                    {'servers': {'x': {'args': [5]}}},
                    {'servers': {'x': {'env': {'X': 5}}}},
                    {'servers': {'x': {'headers': None}}},
                    {'mcpServers': [], 'servers': {'x': {}}}):
            with self.subTest(cfg=cfg), self.assertRaises(ValueError):
                audit_mcp_config_credentials(cfg)

    def test_run_keys_read_only_and_errors(self):
        registry = MagicMock()
        registry.HKEY_CURRENT_USER = 'HKCU'
        registry.HKEY_LOCAL_MACHINE = 'HKLM'
        registry.KEY_READ = 0x20019
        registry.KEY_WOW64_32KEY = 0x200
        registry.KEY_WOW64_64KEY = 0x100
        registry.REG_SZ, registry.REG_EXPAND_SZ = 1, 2
        registry.QueryInfoKey.return_value = (0, 1, 0)
        registry.EnumValue.return_value = ('helper', r'C:\test\.mainhelper', 1)
        with patch.object(auditor.sys, 'platform', 'win32'), patch.dict(sys.modules, {'winreg': registry}):
            safe, findings = auditor.audit_windows_run_keys()
            self.assertFalse(safe)
            self.assertTrue(findings)
            self.assertEqual(registry.OpenKey.call_count, 8)
            for call in registry.OpenKey.call_args_list:
                self.assertEqual(call.args[2], 0)
                self.assertIn(call.args[3], (0x20119, 0x20219))
            registry.SetValue.assert_not_called()
            registry.EnumValue.return_value = ('normal', r'C:\Program Files\app.exe', 1)
            self.assertTrue(auditor.audit_windows_run_keys()[0])
            registry.OpenKey.side_effect = PermissionError('denied')
            with self.assertRaises(OSError):
                auditor.audit_windows_run_keys()
            registry.OpenKey.side_effect = FileNotFoundError()
            self.assertTrue(auditor.audit_windows_run_keys()[0])

    def test_non_windows_run_keys_explicit_skip(self):
        with patch.object(auditor.sys, 'platform', 'linux'), patch('builtins.print') as out:
            self.assertIsNone(auditor.audit_windows_run_keys()[0])
            self.assertIn('[SKIP]', str(out.call_args_list))

    def test_cli_invalid_inputs_and_missing_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for flag, content in (('--audit-accounts-json', '[]'), ('--audit-mcp-config', '{}'),
                                  ('--audit-mcp-config', '{'), ('--audit-mcp-config', '')):
                p = root / 'input.json'
                p.write_text(content, encoding='utf-8')
                result = subprocess.run([sys.executable, '-B', auditor.__file__, flag, str(p)], capture_output=True)
                self.assertEqual(result.returncode, 2, result.stdout)
            for args in ([], ['--scan-dir', str(root / 'absent')], ['--scan-dir', str(p)],
                         ['--audit-mcp-config', str(root / 'absent')]):
                result = subprocess.run([sys.executable, '-B', auditor.__file__, *args], capture_output=True)
                self.assertEqual(result.returncode, 2, result.stdout)


class McpCredentialRound2(unittest.TestCase):
    """第二輪：env/headers/url 查詢參數的寫死憑證與鍵名規則（字串組合避免真實 token 字面值）。"""

    GHP = "gh" + "p_" + "a" * 36
    YA = "ya" + "29." + "a0AfH6SMBsynthetic"

    def _bad(self, cfg):
        safe, found = audit_mcp_config_credentials({'mcpServers': {'x': cfg}})
        self.assertFalse(safe, cfg)
        return found

    def test_env_hardcoded_token_and_sensitive_key_name(self):
        self._bad({'env': {'GITHUB_TOKEN': self.GHP}})
        self._bad({'env': {'MY_SECRET': 'plain-value'}})
        self._bad({'env': {'DB_PASSWORD': 'hunter2'}})
        self._bad({'env': {'SERVICE_CREDENTIAL': 'abc'}})
        self._bad({'env': {'NOTE': 'use ' + self.GHP}})

    def test_url_query_and_userinfo(self):
        self._bad({'url': 'https://h/mcp?access_token=' + self.YA})
        self._bad({'url': 'https://h/mcp?x=1&api_key=realvalue'})
        self._bad({'url': 'https://h/mcp?q=' + self.GHP})
        self._bad({'serverUrl': 'https://user:hunter2@h/mcp'})

    def test_header_api_key(self):
        self._bad({'headers': {'X-API-Key': 'realvalue12345'}})
        self._bad({'headers': {'X-Custom': 'xox' + 'b-123456789-abcdefgh'}})

    def test_known_token_patterns(self):
        for token in ('sk' + '-' + 'a' * 24, 'sk' + '-ant-' + 'a' * 20, 'xox' + 'p-123456789-abc',
                      'github' + '_pat_' + 'A' * 30, 'AK' + 'IA' + 'A' * 16):
            with self.subTest(token=token[:6]):
                self._bad({'env': {'NOTE': token}})
                self._bad({'args': [token]})

    def test_placeholders_and_benign_values_pass(self):
        for cfg in ({'env': {'GITHUB_TOKEN': '${GITHUB_TOKEN}', 'API_KEY': '%API_KEY%',
                             'SECRET': '{{secret}}', 'NODE_ENV': 'production', 'EMPTY_TOKEN': ''}},
                    {'headers': {'X-API-Key': '$API_KEY', 'Authorization': 'Bearer ${T}'}},
                    {'url': 'https://h/mcp?access_token=${TOKEN}&mode=fast'},
                    {'url': 'https://h/mcp?page=2'},
                    {'url': 'https://user:${PW}@h/mcp'},
                    {'args': ['-y', '@scope/risk-tool', '--task-name', 'ask-me-anything-please']}):
            with self.subTest(cfg=cfg):
                self.assertTrue(audit_mcp_config_credentials({'mcpServers': {'x': cfg}})[0])

    def test_url_must_be_string(self):
        with self.assertRaises(ValueError):
            audit_mcp_config_credentials({'mcpServers': {'x': {'url': ['https://h']}}})

    def test_cli_exit_codes_for_new_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'm.json'
            p.write_text(json.dumps({'mcpServers': {'x': {'env': {'GITHUB_TOKEN': self.GHP}}}}), encoding='utf-8')
            r = subprocess.run([sys.executable, '-B', auditor.__file__, '--audit-mcp-config', str(p)], capture_output=True)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertNotIn(self.GHP.encode(), r.stdout + r.stderr)


class Review20261121CloudAudit(unittest.TestCase):
    """2026-11-21 攻擊者角度覆核（REVIEW.md C-1～C-7）找到的漏報，每一項都要維持修正。"""

    GHP = "gh" + "p_" + "a" * 36
    GHO = "gh" + "o_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    AIZA = "AI" + "za" + "Sy" + "A" * 33
    ASIA = "AS" + "IA" + "ABCDEFGHIJKLMNOP"

    def _bad(self, cfg):
        safe, found = audit_mcp_config_credentials({'mcpServers': {'x': cfg}})
        self.assertFalse(safe, cfg)
        return found

    def _good(self, cfg):
        safe, found = audit_mcp_config_credentials({'mcpServers': {'x': cfg}})
        self.assertTrue(safe, (cfg, found))

    def test_more_known_token_patterns(self):
        for token in (self.GHO, "gh" + "s_" + "a" * 36, "gh" + "u_" + "a" * 36, "gh" + "r_" + "a" * 36,
                      self.AIZA, self.ASIA, "gl" + "pat-" + "a" * 20, "h" + "f_" + "a" * 34,
                      "np" + "m_" + "a" * 36, "xo" + "xs-" + "1234567890-abc", "xa" + "pp-" + "1-A0B1C2D3E4",
                      "sk" + "_live_" + "a" * 24, "-----BEGIN " + "PRIVATE KEY-----\nMIIabc"):
            with self.subTest(token=token[:6]):
                self._bad({'command': 'x', 'env': {'NOTE': token}})
                self._bad({'command': 'x', 'args': [token]})

    def test_command_string_is_scanned(self):
        self._bad({'command': 'npx srv --token ' + self.GHP})
        self._bad({'command': 'cmd /c srv.exe --header "Authorization: Bearer abcdef0123456789"'})
        self._bad({'command': 'srv --api-key=' + 'abcdef0123456789xyz'})
        self._good({'command': 'npx -y @modelcontextprotocol/server-filesystem C:/work'})

    def test_args_sensitive_flag_with_value(self):
        self._bad({'command': 'npx', 'args': ['--api-key', 'abcdef0123456789xyz']})
        self._bad({'command': 'npx', 'args': ['--token=abcdef0123456789xyz']})
        self._bad({'command': 'npx', 'args': ['--client-secret', 'plainsecretvalue']})
        self._good({'command': 'npx', 'args': ['--api-key', '${API_KEY}']})
        self._good({'command': 'npx', 'args': ['--token-file', '/run/secrets/token']})
        self._good({'command': 'npx', 'args': ['--keyboard-layout', 'us', '--max-tokens', '4096']})
        self._good({'command': 'npx', 'args': ['--api-key', '--verbose']})

    def test_header_argument_with_sensitive_name(self):
        # ai-inbox REVIEW.md 16.2（T-20261107-05）：mcp-remote --header 是 Claude Desktop 傳標頭最常見的寫法
        hexkey = '0123456789abcdef' * 2
        for args in (['mcp-remote', 'https://h/mcp', '--header', 'X-Api-Key:' + hexkey],
                     ['mcp-remote', 'https://h/mcp', '--header', 'X-Api-Key: ' + hexkey],
                     ['x', '-H', 'X-Auth-Token:' + hexkey],
                     ['x', '--header=X-Api-Key:' + hexkey],
                     ['x', '--header', 'Cookie: session=' + hexkey],
                     ['server.js', '--api-key=' + hexkey]):
            with self.subTest(args=args[-1][:14]):
                self._bad({'command': 'npx', 'args': args})
        self._bad({'command': 'npx mcp-remote https://h/mcp --header "X-Api-Key: ' + hexkey + '"'})
        for args in (['mcp-remote', 'https://h/mcp', '--header', 'X-Api-Key:${API_KEY}'],
                     ['mcp-remote', 'https://h/mcp', '--header', 'X-Api-Key: Bearer ${T}'],
                     ['x', '--header', 'Accept: application/json'],
                     ['x', 'C:/work', 'https://h/mcp']):
            with self.subTest(ok=args[-1][:14]):
                self._good({'command': 'npx', 'args': args})

    def test_other_fields_and_nested_objects_are_scanned(self):
        self._bad({'url': 'https://h/mcp', 'oauth': {'clientId': 'abc', 'clientSecret': 'plainsecretvalue'}})
        self._bad({'url': 'https://h/mcp', 'auth': {'type': 'bearer', 'value': self.GHP}})
        self._bad({'command': 'x', 'cwd': 'C:/work/' + self.AIZA})
        self._good({'url': 'https://h/mcp', 'oauth': {'clientId': 'abc', 'tokenUrl': 'https://h/token',
                                                      'scopes': ['read']}, 'timeout': 30})

    def test_cookie_header_is_a_credential(self):
        self._bad({'url': 'https://h/mcp', 'headers': {'Cookie': 'session=abcdef0123456789'}})
        self._good({'url': 'https://h/mcp', 'headers': {'Cookie': '${SESSION_COOKIE}'}})

    def test_known_token_wrapped_in_angle_or_brace_placeholder_still_counts(self):
        self._bad({'command': 'x', 'env': {'NOTE': '<' + self.GHP + '>'}})
        self._bad({'command': 'x', 'env': {'NOTE': '{{' + self.GHP + '}}'}})

    def test_nested_project_and_vscode_server_maps_are_scanned(self):
        claude_json = {'mcpServers': {'a': {'command': 'x'}},
                       'projects': {'C:/p': {'mcpServers': {'b': {'command': 'x', 'env': {'API_KEY': self.GHP}}}},
                                    'C:/q': {'mcpServers': {}}}}
        safe, found = audit_mcp_config_credentials(claude_json)
        self.assertFalse(safe)
        self.assertEqual([f['server'] for f in found], ['b'])
        only_nested = {'projects': {'C:/p': {'mcpServers': {'b': {'command': 'x', 'env': {'API_KEY': self.GHP}}}}}}
        self.assertFalse(audit_mcp_config_credentials(only_nested)[0])
        vscode = {'mcp': {'servers': {'b': {'command': 'x', 'env': {'API_KEY': self.GHP}}}}}
        self.assertFalse(audit_mcp_config_credentials(vscode)[0])
        clean_nested = {'projects': {'C:/p': {'mcpServers': {'b': {'command': 'x'}}}}}
        self.assertTrue(audit_mcp_config_credentials(clean_nested)[0])
        for cfg in ({'projects': {'C:/p': {'mcpServers': {}}}}, {'projects': {'C:/p': {'mcpServers': []}}},
                    {'projects': {'C:/p': {'mcpServers': {'b': []}}}}):
            with self.subTest(cfg=cfg), self.assertRaises(ValueError):
                audit_mcp_config_credentials(cfg)

    def _cli(self, *args):
        return subprocess.run([sys.executable, '-B', auditor.__file__, *args], capture_output=True)

    def test_cli_duplicate_keys_are_input_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'm.json'
            p.write_text('{"mcpServers":{"s":{"command":"x","env":{"API_KEY":"' + self.GHP + '"},"env":{}}}}',
                         encoding='utf-8')
            r = self._cli('--audit-mcp-config', str(p))
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertNotIn(self.GHP.encode(), r.stdout + r.stderr)
            p.write_text('[{"email":"a@p.iam.gserviceaccount.com","roles":["roles/owner"],"roles":[],'
                         '"createTime":"2026-01-01T00:00:00Z"}]', encoding='utf-8')
            self.assertEqual(self._cli('--audit-accounts-json', str(p)).returncode, 2)

    def test_roles_with_whitespace_case_and_impersonation_roles(self):
        for role in (' roles/owner', 'Roles/Owner ', 'roles/iam.serviceAccountTokenCreator',
                     'roles/iam.serviceAccountUser', 'roles/iam.workloadIdentityUser'):
            with self.subTest(role=role):
                accs = [{'email': 'x@p.iam.gserviceaccount.com', 'roles': [role],
                         'createTime': '2026-01-01T00:00:00Z'}]
                self.assertFalse(audit_service_account_anomalies(accs)[0])

    def test_burst_check_is_linear_on_large_input(self):
        accs = [{'email': f'a{i}@p.iam.gserviceaccount.com', 'roles': [],
                 'createTime': '2026-01-01T00:00:00Z'} for i in range(20000)]
        start = time.monotonic()
        safe, found = audit_service_account_anomalies(accs)
        self.assertLess(time.monotonic() - start, 5.0)
        self.assertFalse(safe)
        self.assertIn('20000', found[-1]['reasons'][0])

    def test_scan_dir_follows_directory_links_without_looping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'scan'
            other = Path(tmp) / 'other'
            root.mkdir()
            other.mkdir()
            (other / '.mainhelper').write_text('x', encoding='utf-8')
            try:
                os.symlink(other, root / 'linked', target_is_directory=True)
                os.symlink(root, other / 'back', target_is_directory=True)
            except (OSError, NotImplementedError):
                if sys.platform != 'win32':
                    self.skipTest('無權限建立符號連結')
                # Windows 一般帳號不能建符號連結，改用 junction（同樣是目錄連結，也能繞回自己）
                for link, target in ((root / 'linked', other), (other / 'back', root)):
                    r = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)], capture_output=True)
                    if r.returncode != 0:
                        self.skipTest('無法建立 junction')
            safe, found = audit_local_persistence_artifacts(str(root))
            self.assertFalse(safe)
            self.assertEqual(len(found), 1)


if __name__ == "__main__":
    unittest.main()
