"""Unified command parser and dispatcher for interactive and direct CLI execution.

Supported commands:
- help
- system
- doctor
- audit
- network
- processes
- users [--sessions | --admins]
- auth --input <file> [--threshold N] [--window SECONDS]
- report --format <json|csv>
- history
- clear
- exit

Security policy:
- Never falls through to operating-system shell execution.
- Validates all arguments explicitly and provides clear error messages.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import sys
from typing import Sequence

from sentinel import __app_name__, __description__, __version__
from sentinel.checks.authentication import render_auth_command
from sentinel.checks.network import render_network_command
from sentinel.checks.processes import render_processes_command
from sentinel.checks.system import (
    render_audit_command,
    render_doctor,
    render_system_info,
)
from sentinel.checks.users import render_users_command
from sentinel.findings import FindingStore
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.reporting import render_report_command
from sentinel.utils.formatting import TerminalStyle, format_table, safe_stream_write
from sentinel.utils.validation import sanitize_output_text

SUPPORTED_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("help", "help", "Display available LINUY commands and usage examples."),
    ("system", "system", "Display OS, Python version, available utilities, and permission limits."),
    ("doctor", "doctor", "Run read-only application health, dependency, and permission checks."),
    ("audit", "audit", "Run read-only defensive host configuration and permission checks."),
    ("network", "network", "Inspect local listening TCP/UDP endpoints and active connections."),
    ("processes", "processes", "Inspect running local processes without exposing cmdline secrets."),
    ("users", "users [--sessions | --admins]", "Enumerate configured accounts, active sessions, and admins."),
    ("auth", "auth --input <file>", "Normalize and analyze authentication logs for brute-force leads."),
    ("report", "report --format <json|csv>", "Export collected findings to a validated JSON or CSV report."),
    ("history", "history", "Display commands executed during the current interactive session."),
    ("clear", "clear", "Clear the terminal display."),
    ("exit", "exit", "Exit the interactive LINUY shell."),
)


class CommandParseError(Exception):
    """Raised when command arguments fail validation without calling sys.exit."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser subclass that raises CommandParseError instead of exiting the process."""

    def error(self, message: str) -> None:
        raise CommandParseError(message)


@dataclass(frozen=True)
class DispatchResult:
    """Result of executing a single LINUY command."""

    command: str
    output: str
    exit_code: int = 0
    should_exit: bool = False
    should_clear: bool = False


def render_help_text(style: TerminalStyle | None = None) -> str:
    """Format the help guide and usage examples."""
    st = style or TerminalStyle(use_color=False)
    rows = [[cmd, syntax, desc] for cmd, syntax, desc in SUPPORTED_COMMANDS]
    lines = [
        st.header("LINUY COMMAND REFERENCE"),
        "Execution mode: Read-only | Scope: Local | Arbitrary OS command execution is disabled.\n",
        format_table(
            headers=["Command", "Syntax", "Description"],
            rows=rows,
            max_col_width=56,
        ),
        st.section("Direct CLI Usage Examples"),
        "  linuy",
        "  linuy --help",
        "  linuy --version",
        "  linuy system",
        "  linuy doctor",
        "  linuy audit",
        "  linuy network",
        "  linuy processes",
        "  linuy users",
        "  linuy users --sessions",
        "  linuy users --admins",
        "  linuy auth --input samples/auth_events.jsonl",
        "  linuy report --format json",
        "  linuy report --format csv",
    ]
    return "\n".join(lines)


def split_command_line(line: str) -> list[str]:
    """Tokenize an interactive command line safely without interpreting shell metacharacters."""
    stripped = line.strip()
    if not stripped:
        return []
    try:
        tokens = shlex.split(stripped, posix=(os.name != "nt"))
        if os.name == "nt":
            cleaned_tokens: list[str] = []
            for tok in tokens:
                if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
                    cleaned_tokens.append(tok[1:-1])
                else:
                    cleaned_tokens.append(tok)
            tokens = cleaned_tokens
        return tokens
    except ValueError as exc:
        raise CommandParseError(f"Malformed command quoting: {sanitize_output_text(str(exc), 120)}") from exc


def dispatch_tokens(
    tokens: Sequence[str],
    store: FindingStore,
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
    project_root: Path | None = None,
    history: Sequence[str] = (),
) -> DispatchResult:
    """Validate and execute a tokenized command against shared application logic."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()

    if not tokens:
        return DispatchResult(command="", output="", exit_code=0)

    cmd = tokens[0].lower().strip()
    rest = list(tokens[1:])

    if cmd == "help":
        if rest:
            return DispatchResult(
                command="help",
                output=f"{st.format_status('ERROR')} 'help' takes no arguments. Usage: help",
                exit_code=2,
            )
        return DispatchResult(command="help", output=render_help_text(st), exit_code=0)

    if cmd in ("exit", "quit"):
        if rest:
            return DispatchResult(
                command="exit",
                output=f"{st.format_status('ERROR')} 'exit' takes no arguments.",
                exit_code=2,
            )
        return DispatchResult(
            command="exit",
            output="Exiting LINUY.",
            exit_code=0,
            should_exit=True,
        )

    if cmd == "clear":
        if rest:
            return DispatchResult(
                command="clear",
                output=f"{st.format_status('ERROR')} 'clear' takes no arguments.",
                exit_code=2,
            )
        return DispatchResult(command="clear", output="", exit_code=0, should_clear=True)

    if cmd == "history":
        if rest:
            return DispatchResult(
                command="history",
                output=f"{st.format_status('ERROR')} 'history' takes no arguments.",
                exit_code=2,
            )
        if not history:
            return DispatchResult(command="history", output="No commands recorded in session history.", exit_code=0)
        hist_lines = [st.header("SESSION COMMAND HISTORY")]
        for idx, item in enumerate(history, start=1):
            hist_lines.append(f"  {idx:3d}  {sanitize_output_text(item, 160)}")
        return DispatchResult(command="history", output="\n".join(hist_lines), exit_code=0)

    if cmd == "system":
        if rest:
            return DispatchResult(
                command="system",
                output=f"{st.format_status('ERROR')} 'system' does not accept extra arguments. Usage: system",
                exit_code=2,
            )
        out, findings = render_system_info(profile=pf, style=st)
        store.add_findings(findings, source_command="system")
        return DispatchResult(command="system", output=out, exit_code=0)

    if cmd == "doctor":
        if rest:
            return DispatchResult(
                command="doctor",
                output=f"{st.format_status('ERROR')} 'doctor' does not accept extra arguments. Usage: doctor",
                exit_code=2,
            )
        out, findings = render_doctor(
            project_root=project_root,
            profile=pf,
            style=st,
            report_dir_override=store.report_dir if project_root is None else None,
        )
        store.add_findings(findings, source_command="doctor")
        return DispatchResult(command="doctor", output=out, exit_code=0)

    if cmd == "audit":
        if rest:
            return DispatchResult(
                command="audit",
                output=f"{st.format_status('ERROR')} 'audit' does not accept extra arguments. Usage: audit",
                exit_code=2,
            )
        out, findings = render_audit_command(profile=pf, style=st)
        store.add_findings(findings, source_command="audit")
        return DispatchResult(command="audit", output=out, exit_code=0)

    if cmd == "network":
        if rest:
            return DispatchResult(
                command="network",
                output=f"{st.format_status('ERROR')} 'network' does not accept extra arguments. Usage: network",
                exit_code=2,
            )
        out, findings = render_network_command(profile=pf, style=st)
        store.add_findings(findings, source_command="network")
        return DispatchResult(command="network", output=out, exit_code=0)

    if cmd == "processes":
        if rest:
            return DispatchResult(
                command="processes",
                output=f"{st.format_status('ERROR')} 'processes' does not accept extra arguments. Usage: processes",
                exit_code=2,
            )
        out, findings = render_processes_command(profile=pf, style=st)
        store.add_findings(findings, source_command="processes")
        return DispatchResult(command="processes", output=out, exit_code=0)

    if cmd == "users":
        parser = _SafeArgumentParser(prog="users", add_help=False)
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--sessions", action="store_true", help="Show active logged-in sessions.")
        group.add_argument("--admins", action="store_true", help="Show administrative accounts.")
        try:
            ns = parser.parse_args(rest)
        except CommandParseError as exc:
            return DispatchResult(
                command="users",
                output=(
                    f"{st.format_status('ERROR')} Invalid arguments for 'users': {sanitize_output_text(str(exc), 160)}\n"
                    "  Usage: users | users --sessions | users --admins"
                ),
                exit_code=2,
            )
        out, findings = render_users_command(
            sessions_only=bool(ns.sessions),
            admins_only=bool(ns.admins),
            profile=pf,
            style=st,
        )
        src_label = "users --sessions" if ns.sessions else ("users --admins" if ns.admins else "users")
        store.add_findings(findings, source_command=src_label)
        return DispatchResult(command="users", output=out, exit_code=0)

    if cmd == "auth":
        parser = _SafeArgumentParser(prog="auth", add_help=False)
        parser.add_argument("--input", dest="input_file", required=True, help="Path to authentication log file.")
        parser.add_argument(
            "--threshold",
            type=int,
            default=5,
            help="Failed login threshold within window (default: 5).",
        )
        parser.add_argument(
            "--window",
            type=int,
            default=300,
            help="Sliding time window in seconds (default: 300).",
        )
        try:
            ns = parser.parse_args(rest)
        except CommandParseError as exc:
            return DispatchResult(
                command="auth",
                output=(
                    f"{st.format_status('ERROR')} Invalid arguments for 'auth': {sanitize_output_text(str(exc), 160)}\n"
                    "  Usage: auth --input <file> [--threshold 5] [--window 300]"
                ),
                exit_code=2,
            )
        if ns.threshold < 1 or ns.window < 1:
            return DispatchResult(
                command="auth",
                output=f"{st.format_status('ERROR')} --threshold and --window must be positive integers.",
                exit_code=2,
            )
        out, findings = render_auth_command(
            input_file=ns.input_file,
            base_dir=project_root,
            failure_threshold=ns.threshold,
            window_seconds=ns.window,
            profile=pf,
            style=st,
        )
        has_err = any(f.status == "ERROR" for f in findings)
        store.add_findings(findings, source_command=f"auth --input {ns.input_file}")
        return DispatchResult(command="auth", output=out, exit_code=1 if has_err else 0)

    if cmd == "report":
        parser = _SafeArgumentParser(prog="report", add_help=False)
        parser.add_argument(
            "--format",
            dest="fmt",
            required=True,
            choices=["json", "csv"],
            help="Output report format: json or csv.",
        )
        try:
            ns = parser.parse_args(rest)
        except CommandParseError as exc:
            return DispatchResult(
                command="report",
                output=(
                    f"{st.format_status('ERROR')} Invalid arguments for 'report': {sanitize_output_text(str(exc), 160)}\n"
                    "  Usage: report --format json | report --format csv"
                ),
                exit_code=2,
            )
        out, path = render_report_command(fmt=ns.fmt, store=store, profile=pf, style=st)
        return DispatchResult(command="report", output=out, exit_code=0 if path is not None else 1)

    clean_unknown = sanitize_output_text(cmd, 48)
    return DispatchResult(
        command=clean_unknown,
        output=(
            f"{st.format_status('ERROR')} Unknown command '{clean_unknown}'. "
            "LINUY does not execute operating-system shell commands.\n"
            "  Type 'help' to view supported defensive inspection commands."
        ),
        exit_code=2,
    )


def _silence_broken_stdout() -> None:
    """Silence sys.stdout cleanly when a downstream pipe consumer (e.g. head) closes early."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            if hasattr(sys.stdout, "fileno"):
                os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)
    except OSError:
        pass


def main(argv: Sequence[str] | None = None) -> int:
    """Run LINUY in direct CLI mode or launch the interactive shell."""
    from sentinel import resolve_default_report_dir
    from sentinel.shell import SentinelShell

    args = list(sys.argv[1:] if argv is None else argv)

    use_color: bool | None = None
    if "--no-color" in args:
        use_color = False
        args = [a for a in args if a != "--no-color"]

    report_dir = resolve_default_report_dir()
    style = TerminalStyle(use_color=use_color)
    profile = detect_platform()
    store = FindingStore(report_dir=report_dir)

    try:
        if not args:
            shell = SentinelShell(
                store=store,
                profile=profile,
                style=style,
                project_root=None,
            )
            return shell.run()

        if len(args) == 1 and args[0] in ("-h", "--help"):
            safe_stream_write(sys.stdout, render_help_text(style) + "\n")
            return 0

        if len(args) == 1 and args[0] in ("-V", "--version"):
            safe_stream_write(
                sys.stdout,
                f"{__app_name__} v{__version__} -- {__description__}\n",
            )
            return 0

        result = dispatch_tokens(
            tokens=args,
            store=store,
            profile=profile,
            style=style,
            project_root=None,
        )
        if result.should_clear:
            if style.use_color:
                safe_stream_write(sys.stdout, "\033[2J\033[H")
            else:
                safe_stream_write(sys.stdout, "\n" * 3)
            return result.exit_code
        if result.output:
            safe_stream_write(sys.stdout, result.output + "\n")
        return result.exit_code
    except BrokenPipeError:
        _silence_broken_stdout()
        return 0
