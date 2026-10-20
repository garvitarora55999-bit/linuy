"""Custom interactive shell ('linuy >') for LINUY.

Implements the interactive CLI interface:
- Compact startup screen with the original LINUY ASCII logo, version, OS, Read-only Mode, and Local Scope.
- Consistent 'linuy > ' prompt.
- Session command history ('history'), screen clearing ('clear'), and clean exit ('exit').
- In-memory readline command completion and line editing on interactive terminals.
- Strictly routes commands through dispatch_tokens; never executes OS commands.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable, TextIO

from sentinel import resolve_default_report_dir
from sentinel.commands import (
    SUPPORTED_COMMANDS,
    CommandParseError,
    dispatch_tokens,
    split_command_line,
)
from sentinel.findings import FindingStore
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import (
    TerminalStyle,
    format_startup_banner,
    safe_stream_write,
)

_COMPLETION_WORDS: tuple[str, ...] = (
    *(cmd for cmd, _, _ in SUPPORTED_COMMANDS),
    "--sessions",
    "--admins",
    "--input",
    "--threshold",
    "--window",
    "--format",
    "json",
    "csv",
    "samples/auth_events.jsonl",
    "samples/linux_auth.log",
    "samples/windows_security_events.json",
)


def _configure_interactive_readline() -> None:
    """Enable in-memory line editing and tab completion when connected to a real TTY."""
    try:
        stdin_tty = bool(getattr(sys.stdin, "isatty", lambda: False)())
        if not stdin_tty:
            return
        import readline  # type: ignore

        def _completer(text: str, state: int) -> str | None:
            clean = text.strip().lower()
            matches = [w for w in _COMPLETION_WORDS if w.lower().startswith(clean)]
            if 0 <= state < len(matches):
                return matches[state]
            return None

        readline.set_completer(_completer)
        if hasattr(readline, "set_completer_delims"):
            readline.set_completer_delims(" \t\n;")
        if hasattr(readline, "parse_and_bind"):
            doc = getattr(readline, "__doc__", "") or ""
            if "libedit" in doc.lower():
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
    except Exception:
        pass


class SentinelShell:
    """Interactive read-only defensive security CLI shell for LINUY."""

    PROMPT = "linuy > "

    def __init__(
        self,
        store: FindingStore | None = None,
        profile: PlatformProfile | None = None,
        style: TerminalStyle | None = None,
        project_root: Path | None = None,
        input_fn: Callable[[str], str] | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self.project_root = project_root
        default_reports = resolve_default_report_dir(project_root)
        self.store = store or FindingStore(report_dir=default_reports)
        self.profile = profile or detect_platform()
        self.style = style or TerminalStyle()
        self.input_fn = input_fn or input
        self.out = output_stream or sys.stdout
        self.history: list[str] = []

    def _write_line(self, text: str = "") -> None:
        safe_stream_write(self.out, text + "\n")

    def execute_line(self, line: str) -> bool:
        """Process a single interactive command line. Returns True if shell should exit."""
        stripped = line.strip()
        if not stripped:
            return False

        self.history.append(stripped)
        try:
            tokens = split_command_line(stripped)
        except CommandParseError as exc:
            self._write_line(f"{self.style.format_status('ERROR')} {exc}")
            return False

        result = dispatch_tokens(
            tokens=tokens,
            store=self.store,
            profile=self.profile,
            style=self.style,
            project_root=self.project_root,
            history=self.history,
        )

        if result.should_clear:
            if self.style.use_color:
                safe_stream_write(self.out, "\033[2J\033[H")
            else:
                self._write_line("\n" * 2)
            return False

        if result.output:
            self._write_line(result.output)

        return result.should_exit

    def run(self) -> int:
        """Run the interactive 'linuy > ' loop until 'exit' or EOF."""
        if self.input_fn is input:
            _configure_interactive_readline()

        try:
            banner = format_startup_banner(self.profile.display_label, style=self.style)
            self._write_line(banner)

            while True:
                try:
                    line = self.input_fn(self.PROMPT)
                except EOFError:
                    self._write_line("\nExiting LINUY.")
                    return 0
                except KeyboardInterrupt:
                    self._write_line("\nInterrupted. Type 'exit' to quit.")
                    continue
                except UnicodeDecodeError:
                    self._write_line(
                        f"\n{self.style.format_status('ERROR')} Input contained unsupported character encoding."
                    )
                    continue

                should_exit = self.execute_line(line)
                if should_exit:
                    return 0
        except BrokenPipeError:
            return 0


LinuyShell = SentinelShell
