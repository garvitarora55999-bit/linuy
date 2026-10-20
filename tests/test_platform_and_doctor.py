"""Tests for platform detection, system info, doctor health checks, and host audit checks."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel.checks.linux import run_linux_audit_checks
from sentinel.checks.system import render_doctor, render_system_info, run_doctor_checks
from sentinel.checks.windows import inspect_windows_uac_registry
from sentinel.platform_info import detect_platform, parse_os_release
from sentinel.utils.formatting import TerminalStyle


class TestPlatformDoctorAndAudit(unittest.TestCase):
    """Verify OS detection, doctor states, and Linux/Windows audit logic."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.style = TerminalStyle(use_color=False)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_parse_os_release_kali_and_ubuntu(self) -> None:
        os_rel = self.root / "os-release"
        os_rel.write_text(
            'NAME="Kali GNU/Linux"\nID=kali\nPRETTY_NAME="Kali GNU/Linux Rolling"\n',
            encoding="utf-8",
        )
        parsed = parse_os_release(os_rel)
        self.assertEqual(parsed["ID"], "kali")
        self.assertEqual(parsed["PRETTY_NAME"], "Kali GNU/Linux Rolling")

        pf = detect_platform(system_override="Linux", os_release_path=os_rel)
        self.assertEqual(pf.os_family, "Linux")
        self.assertEqual(pf.distro_id, "kali")
        self.assertIn("Kali GNU/Linux Rolling", pf.display_label)

    def test_detect_platform_windows_11_and_unsupported(self) -> None:
        with patch("platform.win32_ver", return_value=("10", "10.0.22631", "SP0", "Multiprocessor Free")):
            pf_win = detect_platform(system_override="Windows")
            self.assertEqual(pf_win.os_family, "Windows")
            self.assertIn("Windows 11", pf_win.display_label)

        pf_other = detect_platform(system_override="FreeBSD")
        self.assertEqual(pf_other.os_family, "Other")

    def test_doctor_does_not_convert_errors_or_warnings_to_pass(self) -> None:
        empty_root = self.root / "incomplete_install"
        empty_root.mkdir()
        pf = detect_platform()
        items, findings = run_doctor_checks(project_root=empty_root, profile=pf)
        by_id = {item.check_id: item for item in items}
        self.assertEqual(by_id["DOC-004"].status, "ERROR")
        self.assertEqual(by_id["DOC-005"].status, "ERROR")

        finding_by_id = {f.finding_id: f for f in findings}
        self.assertEqual(finding_by_id["DOC-004"].status, "ERROR")
        self.assertEqual(finding_by_id["DOC-005"].status, "ERROR")

        out_text, _ = render_doctor(project_root=empty_root, profile=pf, style=self.style)
        self.assertIn("does NOT imply that the host computer is free of security risks", out_text)

    def test_system_info_excludes_environment_secrets(self) -> None:
        with patch.dict("os.environ", {"SUPER_SECRET_API_KEY": "secret_value_12345"}):
            out_text, findings = render_system_info(style=self.style)
            self.assertNotIn("secret_value_12345", out_text)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "PASS")

    def test_linux_audit_synthetic_filesystem_and_sshd_equals_syntax(self) -> None:
        fake_root = self.root / "fake_linux"
        (fake_root / "etc" / "ssh").mkdir(parents=True)
        (fake_root / "proc" / "sys" / "kernel").mkdir(parents=True)
        (fake_root / "proc" / "sys" / "fs").mkdir(parents=True)

        passwd = fake_root / "etc" / "passwd"
        group = fake_root / "etc" / "group"
        shadow = fake_root / "etc" / "shadow"
        sshd_cfg = fake_root / "etc" / "ssh" / "sshd_config"

        passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
        group.write_text("root:x:0:\n", encoding="utf-8")
        shadow.write_text("root:*:19000:0:99999:7:::\n", encoding="utf-8")
        shadow.chmod(0o644)

        # Test PermitRootLogin=yes ('=' delimiter) and inline '# comment' syntax
        sshd_cfg.write_text(
            "# Synthetic sshd_config\nPermitRootLogin=yes # inline comment\nPermitEmptyPasswords no\n",
            encoding="utf-8",
        )

        (fake_root / "proc" / "sys" / "kernel" / "randomize_va_space").write_text("0\n", encoding="utf-8")
        (fake_root / "proc" / "sys" / "fs" / "protected_symlinks").write_text("1\n", encoding="utf-8")
        (fake_root / "proc" / "sys" / "fs" / "protected_hardlinks").write_text("1\n", encoding="utf-8")

        findings = run_linux_audit_checks(platform_label="Ubuntu Test", root_prefix=fake_root)
        by_id = {f.finding_id: f for f in findings}

        self.assertEqual(by_id["AUD-LIN-002"].status, "FINDING")
        self.assertEqual(by_id["AUD-LIN-002"].severity, "CRITICAL")
        self.assertEqual(by_id["AUD-LIN-003"].status, "FINDING")
        self.assertEqual(by_id["AUD-LIN-003"].severity, "HIGH")
        self.assertIn("PermitRootLogin=yes", by_id["AUD-LIN-003"].evidence)
        self.assertEqual(by_id["AUD-LIN-004"].status, "FINDING")
        self.assertIn("randomize_va_space=0", by_id["AUD-LIN-004"].description)

    def test_windows_uac_registry_audit_evaluation(self) -> None:
        f_disabled = inspect_windows_uac_registry({"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 5})
        self.assertEqual(f_disabled.status, "FINDING")
        self.assertEqual(f_disabled.severity, "HIGH")

        f_no_prompt = inspect_windows_uac_registry({"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 0})
        self.assertEqual(f_no_prompt.status, "REVIEW")

        f_secure = inspect_windows_uac_registry({"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 2})
        self.assertEqual(f_secure.status, "PASS")


if __name__ == "__main__":
    unittest.main()
