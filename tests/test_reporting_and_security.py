"""Tests for JSON/CSV reporting, CSV formula-injection defense, path traversal, symlink races, and subprocess safety."""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from sentinel import is_safe_report_directory_path, resolve_default_report_dir
from sentinel.findings import Finding, FindingStatus, FindingStore, Severity
from sentinel.reporting import export_findings_report, render_report_command
from sentinel.utils.validation import (
    read_bounded_file,
    read_validated_input_file,
    resolve_allowlisted_binary,
    run_allowlisted_command,
    sanitize_csv_cell,
    sanitize_output_text,
    split_log_lines,
    validate_input_file,
    validate_report_output_path,
)


class TestReportingAndSecurityControls(unittest.TestCase):
    """Verify report generation, CSV formula sanitization, symlink/FIFO/traversal/UNC/ADS blocks, and PATH hardening."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.report_dir = self.root / "reports"
        self.report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.store = FindingStore(report_dir=self.report_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_empty_findings_refuses_fake_report(self) -> None:
        out, path = render_report_command("json", store=self.store)
        self.assertIsNone(path)
        self.assertIn("no inspection findings have been collected yet", out)

        with self.assertRaises(ValueError):
            export_findings_report([], fmt="json", report_dir=self.report_dir)

    def test_csv_formula_injection_and_json_serialization(self) -> None:
        for dangerous in ("=CMD|' /C calc'!A0", "+SUM(1,1)", "-2+3", "@SUM(A1:A2)", "\t=1+1", "  =HYPERLINK()"):
            cleaned = sanitize_csv_cell(dangerous)
            self.assertTrue(cleaned.startswith("'"), f"Failed to neutralize {dangerous!r} -> {cleaned!r}")

        malicious_finding = Finding(
            finding_id="FND-0001",
            rule_id="TEST-CSV-001",
            title="=1+1 Formula Title",
            severity=Severity.HIGH.value,
            status=FindingStatus.FINDING.value,
            platform="Linux",
            description="+cmd|'/c calc'!A0",
            evidence="password=supersecretvalue123 \x1b[31mRED_ESCAPE\x1b[0m",
            detection_rationale="@malicious_rationale",
            remediation="-investigate",
            timestamp="2026-10-18T12:00:00Z",
            limitations="None",
        )
        self.store.add_findings([malicious_finding], source_command="test")

        self.assertNotIn("supersecretvalue123", malicious_finding.evidence)
        self.assertIn("[REDACTED]", malicious_finding.evidence)
        self.assertNotIn("\x1b", malicious_finding.evidence)

        csv_path = export_findings_report(
            [malicious_finding],
            fmt="csv",
            report_dir=self.report_dir,
            custom_filename="test_report.csv",
        )
        with csv_path.open("r", encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["title"].startswith("'="))
        self.assertTrue(rows[0]["description"].startswith("'+"))
        self.assertTrue(rows[0]["detection_rationale"].startswith("'@"))
        self.assertTrue(rows[0]["remediation"].startswith("'-"))

        json_path = export_findings_report(
            [malicious_finding],
            fmt="json",
            report_dir=self.report_dir,
            custom_filename="test_report.json",
        )
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["report_metadata"]["total_findings"], 1)
        self.assertEqual(payload["findings"][0]["finding_id"], "FND-0001")

        # Verify atomic overwrite prevention
        with self.assertRaises(FileExistsError):
            export_findings_report(
                [malicious_finding],
                fmt="json",
                report_dir=self.report_dir,
                custom_filename="test_report.json",
                allow_overwrite=False,
            )

    def test_user_directory_named_sam_is_permitted_while_sensitive_files_blocked(self) -> None:
        """Regression test for Risk 3.1: /home/sam/... works while /etc/shadow and System32/config/SAM are blocked."""
        sam_home = self.root / "home" / "sam" / "logs"
        sam_home.mkdir(parents=True, exist_ok=True)
        sam_log = sam_home / "auth_events.jsonl"
        sam_log.write_text('{"outcome": "FAILURE", "username": "sam"}\n', encoding="utf-8")

        validated_path = validate_input_file(sam_log)
        self.assertEqual(validated_path, sam_log.resolve())
        resolved_path, content = read_validated_input_file(sam_log)
        self.assertEqual(resolved_path, sam_log.resolve())
        self.assertIn('"username": "sam"', content)

        # However, a file literally named 'sam' or under Windows/System32/config/SAM must still be blocked
        sam_hive_file = sam_home / "SAM"
        sam_hive_file.write_text("hive", encoding="utf-8")
        with self.assertRaises(PermissionError):
            validate_input_file(sam_hive_file)

        win_config_dir = self.root / "Windows" / "System32" / "config"
        win_config_dir.mkdir(parents=True, exist_ok=True)
        win_sys_file = win_config_dir / "system.log"
        win_sys_file.write_text("hive", encoding="utf-8")
        with self.assertRaises(PermissionError):
            validate_input_file(win_sys_file)

    def test_unc_paths_ntfs_ads_and_windows_reserved_device_names_blocked(self) -> None:
        # 1. UNC network share paths and Win32 device namespace paths must be rejected
        for unc_or_dev in (
            r"\\198.51.100.99\share\auth.log",
            "//198.51.100.99/share/auth.log",
            r"\\.\PhysicalDrive0",
            r"\\?\C:\Windows\System32\config\SAM",
        ):
            with self.assertRaises(ValueError):
                validate_input_file(unc_or_dev)

        # 2. NTFS Alternate Data Streams (colon in filename/segment) must be rejected
        for ads_path in ("auth.log:hidden_stream", "samples/auth_events.jsonl:$DATA"):
            with self.assertRaises(ValueError):
                validate_input_file(ads_path, base_dir=self.root)
        with self.assertRaises(ValueError):
            validate_report_output_path(self.report_dir, "report.json:$DATA")

        # 3. Windows reserved device names (with or without extensions) must be rejected
        for reserved in ("CON", "PRN", "AUX", "NUL", "COM1", "LPT1", "con.log", "nul.json", "aux.csv"):
            with self.assertRaises(ValueError):
                validate_input_file(reserved, base_dir=self.root)
            with self.assertRaises(ValueError):
                validate_report_output_path(self.report_dir, reserved)

    def test_adversarial_file_paths_symlinks_fifos_and_report_dir_manipulation(self) -> None:
        # 1. Invalid report filenames (traversal, separators, dotfiles, null bytes)
        for bad_name in (
            "../escape.json",
            "..\\escape.csv",
            "/etc/passwd",
            "sub/file.json",
            "bad\x00.json",
            ".hidden.json",
            "..json",
        ):
            with self.assertRaises(ValueError):
                validate_report_output_path(self.report_dir, bad_name)

        # 2. Forbidden credential / private key paths must raise PermissionError
        ssh_dir = self.root / ".ssh"
        ssh_dir.mkdir()
        id_rsa = ssh_dir / "id_rsa"
        id_rsa.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", encoding="utf-8")
        with self.assertRaises(PermissionError):
            validate_input_file(id_rsa)

        with self.assertRaises(PermissionError):
            validate_input_file("/etc/shadow")

        # 3. Symlinked input file and symlinked parent directory must be rejected
        real_log = self.root / "real_auth.log"
        real_log.write_text("Oct 18 09:00:01 host sshd[10]: Accepted publickey for user from 192.0.2.1 port 22 ssh2\n", encoding="utf-8")
        symlink_log = self.root / "symlink_auth.log"
        symlink_log.symlink_to(real_log)
        with self.assertRaises(ValueError):
            validate_input_file(symlink_log)
        with self.assertRaises(ValueError):
            read_validated_input_file(symlink_log)

        real_subdir = self.root / "real_sub"
        real_subdir.mkdir()
        nested_log = real_subdir / "nested.log"
        nested_log.write_text("Oct 18 09:00:01 host sshd[10]: Accepted publickey for user from 192.0.2.1 port 22 ssh2\n", encoding="utf-8")
        symlink_subdir = self.root / "sym_sub"
        symlink_subdir.symlink_to(real_subdir)
        with self.assertRaises(ValueError):
            validate_input_file(Path("sym_sub/nested.log"), base_dir=self.root)

        # 4. Named pipe (FIFO) input file must be rejected without blocking
        if hasattr(os, "mkfifo"):
            fifo_path = self.root / "malicious.fifo"
            os.mkfifo(fifo_path)
            with self.assertRaises(ValueError):
                validate_input_file(fifo_path)
            with self.assertRaises(ValueError):
                read_validated_input_file(fifo_path)

        # 5. Symlinked report directory or symlinked report target must be rejected
        outside_dir = self.root / "outside_reports"
        outside_dir.mkdir()
        symlink_report_dir = self.root / "symlink_reports"
        symlink_report_dir.symlink_to(outside_dir)
        sample_finding = Finding(
            finding_id="FND-0002",
            rule_id="RULE-1",
            title="Test",
            severity="INFO",
            status="PASS",
            platform="Linux",
            description="ok",
            evidence="ok",
            detection_rationale="ok",
            remediation="ok",
            timestamp="2026-10-18T12:00:00Z",
            limitations="none",
        )
        with self.assertRaises(ValueError):
            export_findings_report(
                [sample_finding],
                fmt="json",
                report_dir=symlink_report_dir,
                custom_filename="out.json",
            )

        outside_secret = outside_dir / "target.json"
        symlink_inside_reports = self.report_dir / "hijack.json"
        symlink_inside_reports.symlink_to(outside_secret)
        with self.assertRaises(ValueError):
            export_findings_report(
                [sample_finding],
                fmt="json",
                report_dir=self.report_dir,
                custom_filename="hijack.json",
            )
        self.assertFalse(outside_secret.exists())

    def test_malicious_executable_in_path_is_ignored(self) -> None:
        """Simulate an attacker placing a trojan 'who' or 'ss' binary earlier in PATH."""
        malicious_bin_dir = self.root / "attacker_bin"
        malicious_bin_dir.mkdir(mode=0o755)
        fake_ss = malicious_bin_dir / ("ss.exe" if os.name == "nt" else "ss")
        fake_ss.write_text("#!/bin/sh\necho PWNED\n", encoding="utf-8")
        fake_ss.chmod(0o755)

        fake_who = malicious_bin_dir / ("who.exe" if os.name == "nt" else "who")
        fake_who.write_text("#!/bin/sh\necho PWNED_WHO\n", encoding="utf-8")
        fake_who.chmod(0o755)

        empty_trusted = self.root / "empty_trusted"
        empty_trusted.mkdir(mode=0o755)

        orig_path = os.environ.get("PATH", "")
        with patch.dict("os.environ", {"PATH": f"{malicious_bin_dir}{os.pathsep}{orig_path}"}):
            resolved_none = resolve_allowlisted_binary("ss", trusted_dirs=[empty_trusted])
            self.assertIsNone(resolved_none)

            cmd_res = run_allowlisted_command("ss", args=[], trusted_dirs=[empty_trusted])
            self.assertTrue(cmd_res.missing_binary)
            self.assertNotIn("PWNED", cmd_res.stdout)

            resolved_who = resolve_allowlisted_binary("who")
            if resolved_who is not None:
                self.assertNotEqual(Path(resolved_who).parent.resolve(), malicious_bin_dir.resolve())

            if os.name != "nt":
                writable_bin_dir = self.root / "custom_bin"
                writable_bin_dir.mkdir(mode=0o755)
                bad_bin = writable_bin_dir / "who"
                bad_bin.write_text("#!/bin/sh\n", encoding="utf-8")
                bad_bin.chmod(0o777)
                self.assertIsNone(
                    resolve_allowlisted_binary(
                        "who",
                        trusted_dirs=[writable_bin_dir],
                        require_root_owner=False,
                    )
                )
                bad_bin.chmod(0o755)
                if os.geteuid() != 0:
                    self.assertIsNone(
                        resolve_allowlisted_binary(
                            "who",
                            trusted_dirs=[writable_bin_dir],
                            require_root_owner=True,
                        )
                    )

    @unittest.skipIf(os.name == "nt", "POSIX BusyBox symlink test")
    def test_busybox_multicall_symlink_resolution(self) -> None:
        """Mocked test for Risk 3.2: safe BusyBox multi-call symlink resolution."""
        trusted_bin = self.root / "trusted_bin"
        trusted_bin.mkdir(mode=0o755)
        busybox_bin = trusted_bin / "busybox"
        busybox_bin.write_text("#!/bin/sh\n", encoding="utf-8")
        busybox_bin.chmod(0o755)

        who_symlink = trusted_bin / "who"
        who_symlink.symlink_to(busybox_bin)

        resolved = resolve_allowlisted_binary(
            "who",
            trusted_dirs=[trusted_bin],
            require_root_owner=False,
        )
        # Must return the symlink path so BusyBox receives 'who' in argv[0]
        self.assertEqual(resolved, str(who_symlink))

        # Symlink pointing to an untrusted binary name must be rejected
        untrusted_target = trusted_bin / "custom_shell"
        untrusted_target.write_text("#!/bin/sh\n", encoding="utf-8")
        untrusted_target.chmod(0o755)
        ss_symlink = trusted_bin / "ss"
        ss_symlink.symlink_to(untrusted_target)
        self.assertIsNone(
            resolve_allowlisted_binary(
                "ss",
                trusted_dirs=[trusted_bin],
                require_root_owner=False,
            )
        )

    def test_allowlisted_subprocess_enforcement_streaming_bounds_and_timeout(self) -> None:
        """Regression test for Defect E: bounded subprocess output collection, timeouts, and cleanup."""
        for disallowed in (
            "bash",
            "sh",
            "cmd",
            "powershell",
            "pwsh",
            "python",
            "curl",
            "wget",
            "nc",
            "nmap",
            "rm",
            "/usr/bin/who",
        ):
            with self.assertRaises(ValueError):
                resolve_allowlisted_binary(disallowed)
            with self.assertRaises(ValueError):
                run_allowlisted_command(disallowed)

        with self.assertRaises(ValueError):
            run_allowlisted_command("who", args=["--bad\x00arg"])
        with self.assertRaises(ValueError):
            run_allowlisted_command("who", args=["--bad\narg"])

        # 1. Test streaming output cap on excessive output (mocked Popen)
        fake_proc = MagicMock()
        fake_proc.stdout = io.BytesIO(b"X" * 50000)
        fake_proc.stderr = io.BytesIO(b"E" * 10000)
        fake_proc.wait.return_value = 0
        fake_proc.returncode = 0
        with patch("sentinel.utils.validation.resolve_allowlisted_binary", return_value="/usr/bin/who"):
            with patch("subprocess.Popen", return_value=fake_proc):
                res = run_allowlisted_command("who", args=[], max_output_bytes=4096)
                self.assertTrue(res.ok)
                self.assertTrue(res.output_truncated)
                self.assertLessEqual(len(res.stdout), 4096)
                self.assertLessEqual(len(res.stderr), 4096)

        # 2. Test timeout handling and child-process kill cleanup (mocked Popen)
        timeout_proc = MagicMock()
        timeout_proc.stdout = io.BytesIO(b"partial output")
        timeout_proc.stderr = io.BytesIO(b"")
        timeout_proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd=["/usr/bin/who"], timeout=0.5),
            0,
        ]
        with patch("sentinel.utils.validation.resolve_allowlisted_binary", return_value="/usr/bin/who"):
            with patch("subprocess.Popen", return_value=timeout_proc):
                res_to = run_allowlisted_command("who", args=[], timeout=0.5)
                self.assertTrue(res_to.timed_out)
                self.assertFalse(res_to.ok)
                self.assertEqual(res_to.returncode, 124)
                timeout_proc.kill.assert_called_once()

        # 3. Test nonzero exit code handling
        fail_proc = MagicMock()
        fail_proc.stdout = io.BytesIO(b"")
        fail_proc.stderr = io.BytesIO(b"Access is denied")
        fail_proc.wait.return_value = 1
        fail_proc.returncode = 1
        with patch("sentinel.utils.validation.resolve_allowlisted_binary", return_value="/usr/bin/who"):
            with patch("subprocess.Popen", return_value=fail_proc):
                res_fail = run_allowlisted_command("who", args=[])
                self.assertFalse(res_fail.ok)
                self.assertTrue(res_fail.permission_denied)
                self.assertEqual(res_fail.returncode, 1)

    @unittest.skipIf(os.name == "nt", "POSIX cache permission check test")
    def test_findings_cache_ownership_and_permission_validation(self) -> None:
        """Regression test for Defect F: cached findings are rejected if file/dir permissions are unsafe."""
        f = Finding(
            finding_id="FND-0099",
            rule_id="RULE-CACHE",
            title="Cache Security Test",
            severity="LOW",
            status="REVIEW",
            platform="Linux",
            description="Cached item",
            evidence="ok",
            detection_rationale="ok",
            remediation="ok",
            timestamp="2026-10-18T12:00:00Z",
            limitations="none",
        )
        self.store.add_findings([f], source_command="audit", persist_cache=True)
        cache_file = self.report_dir / FindingStore.CACHE_FILENAME
        self.assertTrue(cache_file.is_file())

        # Fresh store loads valid 0600 cache
        store2 = FindingStore(report_dir=self.report_dir)
        loaded, meta = store2.get_findings(fallback_to_cache=True)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(meta["source"], "cached_previous_run")

        # Loosen cache file permissions to 0644 (world-readable) -> must be rejected
        os.chmod(cache_file, 0o644)
        store3 = FindingStore(report_dir=self.report_dir)
        loaded_bad, _ = store3.get_findings(fallback_to_cache=True)
        self.assertEqual(loaded_bad, [])

        # Restore file to 0600, but make report_dir world-writable (0777) -> must be rejected
        os.chmod(cache_file, 0o600)
        os.chmod(self.report_dir, 0o777)
        try:
            store4 = FindingStore(report_dir=self.report_dir)
            loaded_bad_dir, _ = store4.get_findings(fallback_to_cache=True)
            self.assertEqual(loaded_bad_dir, [])
        finally:
            os.chmod(self.report_dir, 0o700)

    def test_report_rendering_failure_does_not_leave_empty_or_partial_file(self) -> None:
        """Regression test for Defect F: write failure cleans up partial report file."""
        sample_finding = Finding(
            finding_id="FND-0005",
            rule_id="RULE-ERR",
            title="Write Failure Test",
            severity="INFO",
            status="PASS",
            platform="Linux",
            description="ok",
            evidence="ok",
            detection_rationale="ok",
            remediation="ok",
            timestamp="2026-10-18T12:00:00Z",
            limitations="none",
        )
        bad_writer = MagicMock()
        bad_writer.__enter__.return_value = bad_writer
        bad_writer.write.side_effect = OSError("Simulated disk full error")
        target_file = self.report_dir / "partial_report.json"

        def _fake_open_safe(report_dir: Path, filename: str, allow_overwrite: bool = False):
            target_file.write_text("", encoding="utf-8")
            return target_file, bad_writer

        with patch("sentinel.reporting.open_safe_report_writer", side_effect=_fake_open_safe):
            with self.assertRaises(OSError):
                export_findings_report(
                    [sample_finding],
                    fmt="json",
                    report_dir=self.report_dir,
                    custom_filename="partial_report.json",
                )
        self.assertFalse(target_file.exists(), "Partial/empty report file was not cleaned up on failure")

    def test_report_directory_configuration_validation(self) -> None:
        """Regression test for Risk 3.4: validate LINUY_REPORT_DIR against unsafe system roots."""
        safe_custom = self.root / "my_custom_reports"
        self.assertTrue(is_safe_report_directory_path(str(safe_custom)))

        for unsafe_dir in (
            "/",
            "/etc",
            "/etc/linuy",
            "/usr/local",
            "/proc",
            "/sys",
            "/dev",
            "../relative_escape",
            r"\\198.51.100.1\share\reports",
            r"C:\Windows\System32\reports",
        ):
            self.assertFalse(is_safe_report_directory_path(unsafe_dir), f"Failed to reject {unsafe_dir!r}")

        with patch.dict("os.environ", {"LINUY_REPORT_DIR": "/etc/linuy_reports"}):
            resolved = resolve_default_report_dir()
            self.assertNotEqual(str(resolved), "/etc/linuy_reports")

    def test_sanitize_output_text_strips_bidi_zero_width_separators_and_surrogates(self) -> None:
        """Regression test for Defect D: strip bidi overrides, zero-width chars, surrogates, and Unicode separators."""
        raw = (
            "User \x1b[31mroot\x1b[0m \u202eEVIL_RLO\u202c "
            "zero\u200bwidth\ufeff "
            "sep\u2028line2\u2029para2\x85nel "
            "surrogate:\ud800end "
            "api_key=ABCDEF1234567890"
        )
        cleaned = sanitize_output_text(raw, max_len=300)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\u202e", cleaned)
        self.assertNotIn("\u202c", cleaned)
        self.assertNotIn("\u200b", cleaned)
        self.assertNotIn("\ufeff", cleaned)
        self.assertNotIn("\u2028", cleaned)
        self.assertNotIn("\u2029", cleaned)
        self.assertNotIn("\x85", cleaned)
        self.assertNotIn("\ud800", cleaned)
        self.assertIn("\ufffd", cleaned)
        self.assertNotIn("ABCDEF1234567890", cleaned)
        self.assertIn("api_key=[REDACTED]", cleaned)

        # Ensure split_log_lines only splits on \r\n, \n, \r
        sample_log = "line1\u2028still_line1\u2029still_line1\x85still_line1\nline2\r\nline3\rline4"
        lines = split_log_lines(sample_log)
        self.assertEqual(len(lines), 4)

    def test_bounded_system_file_reads(self) -> None:
        """Regression test for Defect F: read_bounded_file caps reads and rejects symlinks when configured."""
        sample_file = self.root / "bounded.txt"
        sample_file.write_text("A" * 5000, encoding="utf-8")
        text = read_bounded_file(sample_file, max_bytes=1024, allow_symlinks=False)
        self.assertEqual(len(text), 1024)

        sym = self.root / "sym_bounded.txt"
        sym.symlink_to(sample_file)
        with self.assertRaises(ValueError):
            read_bounded_file(sym, max_bytes=1024, allow_symlinks=False)


if __name__ == "__main__":
    unittest.main()
