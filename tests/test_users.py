"""Tests for user account enumeration, active sessions, and administrative memberships."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from sentinel.checks.linux import (
    enumerate_linux_admins,
    enumerate_linux_sessions,
    enumerate_linux_users,
)
from sentinel.checks.users import render_users_command
from sentinel.checks.windows import (
    enumerate_windows_admins,
    enumerate_windows_sessions,
    enumerate_windows_users,
    parse_net_localgroup_admins,
    parse_net_user_detail,
    parse_net_user_list,
    parse_quser_output,
)
from sentinel.platform_info import detect_platform
from sentinel.utils.validation import CommandResult


class TestUsersSessionsAndAdmins(unittest.TestCase):
    """Verify clear separation between configured accounts, logged-in sessions, and admins."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_linux_users_never_reads_shadow_and_classifies_accounts(self) -> None:
        passwd = self.root / "passwd"
        group = self.root / "group"
        login_defs = self.root / "login.defs"
        shadow = self.root / "shadow"

        login_defs.write_text("UID_MIN 1000\n", encoding="utf-8")
        passwd.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
            "bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n",
            encoding="utf-8",
        )
        # Even if a shadow file exists in the same directory, enumerate_linux_users must NEVER read it.
        shadow.write_text("alice:$6$secret_salt$secret_hash_value:19000:0:99999:7:::\n", encoding="utf-8")
        group.write_text(
            "root:x:0:\n"
            "sudo:x:27:alice\n"
            "users:x:100:alice,bob\n",
            encoding="utf-8",
        )

        orig_read_text = Path.read_text

        def _guarded_read_text(path_self: Path, *args, **kwargs) -> str:
            if path_self.name == "shadow":
                raise AssertionError("enumerate_linux_users must NEVER read /etc/shadow!")
            return orig_read_text(path_self, *args, **kwargs)

        with patch.object(Path, "read_text", autospec=True, side_effect=_guarded_read_text):
            users, u_lims = enumerate_linux_users(
                passwd_path=passwd,
                login_defs_path=login_defs,
            )

        self.assertIsNotNone(users)
        assert users is not None
        self.assertEqual(len(users), 4)
        by_name = {u.username: u for u in users}
        self.assertIn("Root / Superuser", by_name["root"].classification)
        self.assertIn("Non-interactive shell", by_name["daemon"].classification)
        self.assertIn("Shell nologin/false", by_name["daemon"].disabled_status)
        self.assertEqual(by_name["alice"].disabled_status, "Unavailable (shadow not read by policy)")
        self.assertEqual(by_name["bob"].disabled_status, "Unavailable (shadow not read by policy)")
        self.assertTrue(any("does not read /etc/shadow" in lim for lim in u_lims))

        admins, _ = enumerate_linux_admins(passwd_path=passwd, group_path=group)
        self.assertIsNotNone(admins)
        assert admins is not None
        admin_names = {a.username: a for a in admins}
        self.assertEqual(set(admin_names.keys()), {"root", "alice"})
        self.assertIn("UID 0", admin_names["root"].privilege_basis)
        self.assertIn("group:sudo", admin_names["alice"].privilege_basis)

    def test_linux_sessions_psutil_path_and_empty_result(self) -> None:
        mock_psutil = MagicMock()
        mock_psutil.users.return_value = [
            SimpleNamespace(name="alice", terminal="pts/0", host="192.0.2.10", started=1700000000.0),
            SimpleNamespace(name="bob", terminal="tty1", host="", started=1700000100.0),
        ]
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            sessions, lims = enumerate_linux_sessions(prefer_psutil=True)
            self.assertIsNotNone(sessions)
            assert sessions is not None
            self.assertEqual(len(sessions), 2)
            self.assertEqual(sessions[0].username, "alice")
            self.assertEqual(sessions[0].source, "psutil.users()")
            self.assertEqual(sessions[1].host, "local")
            self.assertTrue(any("psutil.users()" in lim for lim in lims))

        # Confirmed 0 sessions via psutil.users()
        mock_psutil.users.return_value = []
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            empty_sessions, _ = enumerate_linux_sessions(prefer_psutil=True)
            self.assertEqual(empty_sessions, [])

    def test_linux_sessions_who_fallback_missing_and_permission_denied(self) -> None:
        who_stdout = (
            "alice    pts/0        2026-10-18 09:15 (192.0.2.10)\n"
            "alice    tty1         2026-10-18 08:00\n"
        )
        mock_ok = CommandResult(
            executable="/usr/bin/who",
            args=(),
            returncode=0,
            stdout=who_stdout,
            stderr="",
        )
        # Explicitly disable psutil to deterministically test the 'who' fallback even when psutil is installed
        with patch.dict(sys.modules, {"psutil": None}):
            with patch("sentinel.checks.linux.run_allowlisted_command", return_value=mock_ok):
                sessions, _ = enumerate_linux_sessions(prefer_psutil=False)
                self.assertIsNotNone(sessions)
                assert sessions is not None
                self.assertEqual(len(sessions), 2)
                self.assertEqual(sessions[0].username, "alice")
                self.assertEqual(sessions[0].host, "192.0.2.10")
                self.assertEqual(sessions[0].source, "who (utmp)")

            # Confirmed 0 sessions when 'who' succeeds with empty output
            mock_empty = CommandResult(
                executable="/usr/bin/who",
                args=(),
                returncode=0,
                stdout="",
                stderr="",
            )
            with patch("sentinel.checks.linux.run_allowlisted_command", return_value=mock_empty):
                zero_sessions, _ = enumerate_linux_sessions(prefer_psutil=False)
                self.assertEqual(zero_sessions, [])

            # Missing utility -> None (Unavailable, NOT 0)
            mock_missing = CommandResult(
                executable="who",
                args=(),
                returncode=127,
                stdout="",
                stderr="",
                missing_binary=True,
                error_message="who not found",
            )
            with patch("sentinel.checks.linux.run_allowlisted_command", return_value=mock_missing):
                sessions_none, lims = enumerate_linux_sessions(prefer_psutil=False)
                self.assertIsNone(sessions_none)
                self.assertTrue(any("unavailable" in lim.lower() for lim in lims))

            # Permission error -> None (Unavailable, NOT 0)
            mock_perm = CommandResult(
                executable="/usr/bin/who",
                args=(),
                returncode=126,
                stdout="",
                stderr="Permission denied",
                permission_denied=True,
                error_message="Permission denied",
            )
            with patch("sentinel.checks.linux.run_allowlisted_command", return_value=mock_perm):
                sessions_perm, lims_perm = enumerate_linux_sessions(prefer_psutil=False)
                self.assertIsNone(sessions_perm)
                self.assertTrue(any("Permission denied" in lim for lim in lims_perm))

    def test_windows_sessions_psutil_and_quser_fallback_paths(self) -> None:
        # 1. Test psutil.users() path on Windows
        mock_psutil = MagicMock()
        mock_psutil.users.return_value = [
            SimpleNamespace(name="SecAnalyst", terminal="console", started=1700000000.0)
        ]
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            win_sess, _ = enumerate_windows_sessions(prefer_psutil=True)
            self.assertIsNotNone(win_sess)
            assert win_sess is not None
            self.assertEqual(len(win_sess), 1)
            self.assertEqual(win_sess[0].username, "SecAnalyst")
            self.assertEqual(win_sess[0].source, "psutil.users()")

        # 2. Test quser fallback when psutil raises an exception or is disabled
        quser_out = (
            " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
            ">secanalyst            console             1  Active      none   10/18/2026 9:00 AM\n"
            " backup_op                                 2  Disc        1:15   10/18/2026 7:30 AM\n"
        )
        quser_ok = CommandResult(
            executable=r"C:\Windows\System32\quser.exe",
            args=(),
            returncode=0,
            stdout=quser_out,
            stderr="",
        )
        mock_psutil.users.side_effect = RuntimeError("WTS API error")
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            with patch("sentinel.checks.windows.run_allowlisted_command", return_value=quser_ok):
                sessions_fb, lims_fb = enumerate_windows_sessions(prefer_psutil=True)
                self.assertIsNotNone(sessions_fb)
                assert sessions_fb is not None
                self.assertEqual(len(sessions_fb), 2)
                self.assertEqual(sessions_fb[0].session_name, "console")
                self.assertEqual(sessions_fb[1].session_name, "disconnected")
                self.assertTrue(any("psutil.users() failed" in lim for lim in lims_fb))

        # 3. Test quser 'No User exists for *' -> confirmed 0 sessions ([])
        quser_no_user = CommandResult(
            executable=r"C:\Windows\System32\quser.exe",
            args=(),
            returncode=1,
            stdout="",
            stderr="No User exists for *",
            permission_denied=False,
            missing_binary=False,
            error_message="No User exists for *",
        )
        with patch.dict(sys.modules, {"psutil": None}):
            with patch("sentinel.checks.windows.run_allowlisted_command", return_value=quser_no_user):
                zero_win_sess, _ = enumerate_windows_sessions(prefer_psutil=False)
                self.assertEqual(zero_win_sess, [])

        # 4. Test quser permission denied / missing binary -> None (Unavailable, NOT 0)
        fail_res = CommandResult(
            executable="quser",
            args=(),
            returncode=1,
            stdout="",
            stderr="Access is denied",
            permission_denied=True,
            error_message="Access is denied",
        )
        with patch.dict(sys.modules, {"psutil": None}):
            with patch("sentinel.checks.windows.run_allowlisted_command", return_value=fail_res):
                u_none, _ = enumerate_windows_users()
                s_none, _ = enumerate_windows_sessions(prefer_psutil=False)
                a_none, _ = enumerate_windows_admins()
                self.assertIsNone(u_none)
                self.assertIsNone(s_none)
                self.assertIsNone(a_none)

    def test_windows_net_user_and_admin_parsers(self) -> None:
        net_user_out = (
            "\nUser accounts for \\\\WORKSTATION\n\n"
            "-------------------------------------------------------------------------------\n"
            "Administrator            DefaultAccount           Guest\n"
            "SecAnalyst               WDAGUtilityAccount\n"
            "The command completed successfully.\n"
        )
        names = parse_net_user_list(net_user_out)
        self.assertEqual(
            names,
            ["Administrator", "DefaultAccount", "Guest", "SecAnalyst", "WDAGUtilityAccount"],
        )

        detail_out = (
            "User name                    SecAnalyst\n"
            "Comment                      Local Security Analyst\n"
            "Account active               Yes\n"
            "The command completed successfully.\n"
        )
        active, acc_type = parse_net_user_detail("SecAnalyst", detail_out)
        self.assertEqual(active, "Yes")
        self.assertEqual(acc_type, "Local User Account")

        admins_out = (
            "Alias name     Administrators\n"
            "Members\n\n"
            "-------------------------------------------------------------------------------\n"
            "Administrator\n"
            "CORP\\Domain Admins\n"
            "SecAnalyst\n"
            "The command completed successfully.\n"
        )
        admins = parse_net_localgroup_admins(admins_out)
        self.assertEqual(len(admins), 3)
        self.assertEqual(admins[1].identity, "CORP\\Domain Admins")

        quser_parsed = parse_quser_output(
            " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
            ">secanalyst            console             1  Active      none   10/18/2026 9:00 AM\n"
            " backup_op                                 2  Disc        1:15   10/18/2026 7:30 AM\n"
        )
        self.assertEqual(len(quser_parsed), 2)
        self.assertEqual(quser_parsed[1].session_name, "disconnected")

    def test_unavailable_sessions_not_reported_as_zero_or_pass(self) -> None:
        pf = detect_platform(system_override="Linux")
        mock_missing = CommandResult(
            executable="who",
            args=(),
            returncode=127,
            stdout="",
            stderr="",
            missing_binary=True,
            error_message="who missing",
        )
        with patch("sentinel.checks.linux.run_allowlisted_command", return_value=mock_missing):
            out_text, findings = render_users_command(
                sessions_only=True,
                profile=pf,
                prefer_psutil=False,
            )
            self.assertIn("Unavailable (permission or utility limitation)", out_text)
            self.assertNotIn("Confirmed 0 active", out_text)
            self.assertEqual(findings[0].status, "ERROR")


if __name__ == "__main__":
    unittest.main()
