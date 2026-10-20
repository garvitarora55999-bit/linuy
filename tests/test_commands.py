"""Tests for command parsing, interactive shell routing, packaging, and CWD-independent CLI execution."""

from __future__ import annotations

import configparser
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

import sentinel as sentinel_pkg
from sentinel import __version__
from sentinel.cli import main as console_entry_main
from sentinel.commands import (
    CommandParseError,
    dispatch_tokens,
    main as cli_main,
    split_command_line,
)
from sentinel.findings import FindingStore
from sentinel.shell import SentinelShell
from sentinel.utils.formatting import (
    LINUY_ASCII_LOGO,
    TerminalStyle,
    _enable_windows_vt_mode,
    format_startup_banner,
    get_terminal_width,
    safe_stream_write,
)


class TestCommandParsingAndShell(unittest.TestCase):
    """Verify interactive and direct command routing, argument validation, packaging, and LINUY shell interface."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "reports").mkdir(parents=True, exist_ok=True)
        (self.root / "samples").mkdir(parents=True, exist_ok=True)
        self.store = FindingStore(report_dir=self.root / "reports")
        self.style = TerminalStyle(use_color=False)
        self.repo_root = Path(__file__).resolve().parent.parent

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_package_metadata_and_banner(self) -> None:
        self.assertEqual(sentinel_pkg.__app_name__, "LINUY")
        self.assertEqual(sentinel_pkg.__mode__, "Read-only")
        self.assertEqual(sentinel_pkg.__scope__, "Local")
        self.assertTrue(__version__)

        banner = format_startup_banner("Debian GNU/Linux 12", style=self.style)
        for logo_line in LINUY_ASCII_LOGO:
            self.assertIn(logo_line.rstrip(), banner)
        self.assertIn(f"LINUY v{__version__}", banner)
        self.assertIn("OS / Version   : Debian GNU/Linux 12", banner)
        self.assertIn("Execution mode : Read-only", banner)
        self.assertIn("Scope          : Local", banner)
        self.assertIn("Type 'help' to list available commands", banner)

    def test_startup_banner_legacy_windows_console_encoding_safety(self) -> None:
        """Regression test for Defect H: startup banner and stream writer handle cp437/cp1252/ascii safely."""
        banner = format_startup_banner("Windows 10 (10.0.19045)", style=self.style)
        # Banner must be 100% pure 7-bit ASCII
        banner.encode("ascii")
        banner.encode("cp437")
        banner.encode("cp1252")

        raw_buf = io.BytesIO()
        ascii_stream = io.TextIOWrapper(raw_buf, encoding="ascii", errors="strict")
        safe_stream_write(ascii_stream, banner + "Non-ASCII test: \u2014 \u2603\n")
        written = raw_buf.getvalue().decode("ascii")
        self.assertIn("LINUY", written)

    def test_windows_vt_console_mode_and_color_degradation(self) -> None:
        """Verify Windows VT100 mode activation and graceful plain-text fallback when unavailable."""
        with patch.dict("os.environ", {"NO_COLOR": "1"}):
            st_no_color = TerminalStyle()
            self.assertFalse(st_no_color.use_color)
            self.assertEqual(st_no_color.format_status("ERROR"), "[ERROR]")

        with patch.dict("os.environ", {"TERM": "dumb"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            st_dumb = TerminalStyle()
            self.assertFalse(st_dumb.use_color)

        # Simulate Windows console where SetConsoleMode fails and WT_SESSION/ANSICON are absent
        with patch("sentinel.utils.formatting.os.name", "nt"):
            with patch.dict("os.environ", {}, clear=True):
                fake_ctypes = MagicMock()
                fake_ctypes.windll.kernel32.GetStdHandle.return_value = 10
                fake_ctypes.windll.kernel32.GetConsoleMode.return_value = 0
                with patch.dict(sys.modules, {"ctypes": fake_ctypes}):
                    self.assertFalse(_enable_windows_vt_mode())

                # When WT_SESSION is set (Windows Terminal), VT mode is supported
                with patch.dict("os.environ", {"WT_SESSION": "1"}):
                    with patch.dict(sys.modules, {"ctypes": fake_ctypes}):
                        self.assertTrue(_enable_windows_vt_mode())

    def test_terminal_resize_width_bounds(self) -> None:
        """Verify get_terminal_width clamps extreme narrow and wide terminal sizes safely."""
        with patch("shutil.get_terminal_size", return_value=os.terminal_size((30, 24))):
            self.assertEqual(get_terminal_width(default=100, minimum=60, maximum=160), 60)
        with patch("shutil.get_terminal_size", return_value=os.terminal_size((250, 24))):
            self.assertEqual(get_terminal_width(default=100, minimum=60, maximum=160), 160)
        with patch("shutil.get_terminal_size", return_value=os.terminal_size((92, 24))):
            self.assertEqual(get_terminal_width(default=100, minimum=60, maximum=160), 92)

    def test_broken_pipe_handled_gracefully_without_traceback(self) -> None:
        """Regression test for Defect H: BrokenPipeError returns 0 cleanly without unhandled traceback."""
        with patch("sentinel.commands.safe_stream_write", side_effect=BrokenPipeError("Pipe closed")):
            with patch("sentinel.commands._silence_broken_stdout"):
                rc = cli_main(["--no-color", "system"])
                self.assertEqual(rc, 0)

        class _BrokenPipeStream(io.StringIO):
            def write(self, s: str) -> int:
                raise BrokenPipeError("Simulated head pipe close")

        shell = SentinelShell(
            store=self.store,
            style=self.style,
            project_root=self.root,
            input_fn=lambda _: "exit",
            output_stream=_BrokenPipeStream(),
        )
        self.assertEqual(shell.run(), 0)

    def test_split_command_line_valid_and_malformed(self) -> None:
        tokens = split_command_line('auth --input "samples/auth_events.jsonl"')
        self.assertEqual(tokens, ["auth", "--input", "samples/auth_events.jsonl"])
        self.assertEqual(split_command_line("   "), [])
        with self.assertRaises(CommandParseError):
            split_command_line('auth --input "unclosed_quote')

        # Verify Windows-mode path tokenization preserves backslashes inside quoted paths
        with patch("sentinel.commands.os.name", "nt"):
            win_tokens = split_command_line(r'auth --input "C:\Users\Alice\My Logs\auth_events.jsonl"')
            self.assertEqual(
                win_tokens,
                ["auth", "--input", r"C:\Users\Alice\My Logs\auth_events.jsonl"],
            )

    def test_help_version_clear_and_unknown_command_rejection(self) -> None:
        res_help = dispatch_tokens(["help"], store=self.store, style=self.style, project_root=self.root)
        self.assertEqual(res_help.exit_code, 0)
        self.assertIn("LINUY COMMAND REFERENCE", res_help.output)

        buf_ver = io.StringIO()
        with patch("sys.stdout", buf_ver):
            rc_ver = console_entry_main(["--version"])
        self.assertEqual(rc_ver, 0)
        self.assertIn(f"LINUY v{__version__}", buf_ver.getvalue())

        buf_clear = io.StringIO()
        with patch("sys.stdout", buf_clear):
            rc_clear = console_entry_main(["--no-color", "clear"])
        self.assertEqual(rc_clear, 0)

        for forbidden_cmd in (["whoami"], ["ls", "-la"], ["rm", "-rf", "/"], ["cmd.exe"], ["powershell"]):
            res_unk = dispatch_tokens(forbidden_cmd, store=self.store, style=self.style, project_root=self.root)
            self.assertEqual(res_unk.exit_code, 2)
            self.assertIn("does not execute operating-system shell commands", res_unk.output)

    def test_invalid_extra_arguments_rejected(self) -> None:
        for cmd in ("help", "system", "doctor", "audit", "network", "processes", "history", "clear", "exit"):
            res = dispatch_tokens([cmd, "--unexpected"], store=self.store, style=self.style, project_root=self.root)
            self.assertEqual(res.exit_code, 2)
            self.assertIn("[ERROR]", res.output)

    def test_users_mutually_exclusive_flags(self) -> None:
        res = dispatch_tokens(
            ["users", "--sessions", "--admins"],
            store=self.store,
            style=self.style,
            project_root=self.root,
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Invalid arguments for 'users'", res.output)

    def test_interactive_shell_session_workflow_prompt_and_encoding_recovery(self) -> None:
        prompts_seen: list[str] = []
        events = [
            "help",
            "system",
            "history",
            "clear",
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            "invalid_os_cmd",
            "exit",
        ]
        idx = 0

        def _fake_input(prompt_str: str) -> str:
            nonlocal idx
            prompts_seen.append(prompt_str)
            item = events[idx]
            idx += 1
            if isinstance(item, BaseException):
                raise item
            return item

        out_buf = io.StringIO()
        shell = SentinelShell(
            store=self.store,
            style=self.style,
            project_root=self.root,
            input_fn=_fake_input,
            output_stream=out_buf,
        )
        self.assertEqual(shell.PROMPT, "linuy > ")
        rc = shell.run()
        self.assertEqual(rc, 0)
        self.assertTrue(all(p == "linuy > " for p in prompts_seen))

        text = out_buf.getvalue()
        self.assertIn(f"LINUY v{__version__}", text)
        self.assertIn("Execution mode : Read-only", text)
        self.assertIn("Scope          : Local", text)
        self.assertIn("SYSTEM INFORMATION", text)
        self.assertIn("SESSION COMMAND HISTORY", text)
        self.assertIn("unsupported character encoding", text)
        self.assertIn("Unknown command 'invalid_os_cmd'", text)
        self.assertIn("Exiting LINUY.", text)
        self.assertEqual(text.count(LINUY_ASCII_LOGO[0]), 1)

    def test_cli_entry_point_outside_project_directory(self) -> None:
        """Verify that 'linuy' CLI entry point works when invoked from an arbitrary working directory."""
        outside_cwd = self.root / "arbitrary_cwd"
        outside_cwd.mkdir()
        custom_reports = self.root / "user_state_reports"
        orig_cwd = Path.cwd()
        try:
            os.chdir(outside_cwd)
            with patch.dict("os.environ", {"LINUY_REPORT_DIR": str(custom_reports)}):
                rc_doc = cli_main(["--no-color", "doctor"])
                self.assertEqual(rc_doc, 0)
                rc_auth = cli_main(["--no-color", "auth", "--input", "samples/auth_events.jsonl"])
                self.assertEqual(rc_auth, 0)
                rc_rep = cli_main(["--no-color", "report", "--format", "json"])
                self.assertEqual(rc_rep, 0)
                generated = list(custom_reports.glob("sentinel_report_*.json"))
                self.assertEqual(len(generated), 1)
        finally:
            os.chdir(orig_cwd)

    def test_pyproject_console_script_and_fresh_venv_installation(self) -> None:
        """Verify wheel hygiene, console-script generation, and launching 'linuy' in a fresh venv outside repo."""
        pyproject_text = (self.repo_root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "linuy"', pyproject_text)
        self.assertIn(f'version = "{__version__}"', pyproject_text)
        self.assertIn('linuy = "sentinel.cli:main"', pyproject_text)

        wheel_dir = self.root / "wheelhouse"
        wheel_dir.mkdir(parents=True, exist_ok=True)
        build_cmd = [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "-w",
            str(wheel_dir),
            str(self.repo_root),
        ]
        build_proc = subprocess.run(build_cmd, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(build_proc.returncode, 0, msg=build_proc.stderr)

        wheels = list(wheel_dir.glob("linuy-*.whl"))
        self.assertEqual(len(wheels), 1)
        wheel_path = wheels[0]

        with zipfile.ZipFile(wheel_path, "r") as zf:
            names = zf.namelist()
            # Bundled sample files must be present inside sentinel/samples/
            self.assertIn("sentinel/samples/auth_events.jsonl", names)
            self.assertIn("sentinel/samples/linux_auth.log", names)
            self.assertIn("sentinel/samples/windows_security_events.json", names)
            # Tests, reports, caches, and venvs must NOT be included in the distributable wheel
            for name in names:
                self.assertFalse(name.startswith("tests/"), f"Unexpected test file in wheel: {name}")
                self.assertFalse(name.startswith("reports/"), f"Unexpected report file in wheel: {name}")
                self.assertFalse(name.startswith(".venv/"), f"Unexpected venv file in wheel: {name}")
                self.assertNotIn("__pycache__", name)

            ep_files = [n for n in names if n.endswith("entry_points.txt")]
            self.assertEqual(len(ep_files), 1)
            ep_text = zf.read(ep_files[0]).decode("utf-8")
            cp = configparser.ConfigParser()
            cp.read_string(ep_text)
            self.assertIn("console_scripts", cp.sections())
            self.assertEqual(cp["console_scripts"]["linuy"], "sentinel.cli:main")

        # Install the built wheel into a clean virtual environment and execute the installed 'linuy' binary
        venv_dir = self.root / "clean_venv"
        venv_proc = subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(venv_proc.returncode, 0, msg=venv_proc.stderr)

        venv_py = (
            venv_dir / "Scripts" / "python.exe"
            if os.name == "nt"
            else venv_dir / "bin" / "python3"
        )
        install_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "--python",
                str(venv_py),
                "install",
                "--no-deps",
                str(wheel_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(install_proc.returncode, 0, msg=install_proc.stderr)

        linuy_bin = (
            venv_dir / "Scripts" / "linuy.exe"
            if os.name == "nt"
            else venv_dir / "bin" / "linuy"
        )
        self.assertTrue(linuy_bin.is_file(), f"Expected console script at {linuy_bin}")

        # Launch installed 'linuy' from an outside working directory (/tmp-like folder)
        outside_work = self.root / "outside_work"
        outside_work.mkdir()
        isolated_reports = self.root / "isolated_reports"
        env = dict(os.environ)
        env["LINUY_REPORT_DIR"] = str(isolated_reports)
        env["NO_COLOR"] = "1"

        # 1. Interactive shell launch and clean exit from outside source directory
        interactive_proc = subprocess.run(
            [str(linuy_bin)],
            input="help\ndoctor\nauth --input samples/auth_events.jsonl\nreport --format json\nreport --format csv\nhistory\nexit\n",
            capture_output=True,
            text=True,
            cwd=str(outside_work),
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(interactive_proc.returncode, 0, msg=interactive_proc.stderr)
        self.assertIn(f"LINUY v{__version__}", interactive_proc.stdout)
        self.assertIn("linuy > ", interactive_proc.stdout)
        self.assertIn("APPLICATION HEALTH CHECK (DOCTOR)", interactive_proc.stdout)
        self.assertIn("AUTHENTICATION LOG ANALYSIS", interactive_proc.stdout)
        self.assertIn("REPORT GENERATED SUCCESSFULLY", interactive_proc.stdout)
        self.assertIn("Exiting LINUY.", interactive_proc.stdout)
        self.assertEqual(len(list(isolated_reports.glob("sentinel_report_*.json"))), 1)
        self.assertEqual(len(list(isolated_reports.glob("sentinel_report_*.csv"))), 1)

        # 2. Direct CLI mode (--help and --version) without banner
        help_proc = subprocess.run(
            [str(linuy_bin), "--help"],
            capture_output=True,
            text=True,
            cwd=str(outside_work),
            env=env,
            timeout=15,
            check=False,
        )
        self.assertEqual(help_proc.returncode, 0)
        self.assertIn("LINUY COMMAND REFERENCE", help_proc.stdout)
        self.assertNotIn(LINUY_ASCII_LOGO[0], help_proc.stdout)


if __name__ == "__main__":
    unittest.main()
