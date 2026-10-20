"""Terminal formatting, table layout, and restrained monochrome/ANSI output helpers.

Provides a clean, developer-grade cybersecurity CLI aesthetic for LINUY:
- Original pure-ASCII startup logo for LINUY.
- Defaults to monochrome output in the terminal's normal foreground color,
  using subtle gray (DIM) or white (BOLD) for headings, labels, and separators.
- Reserves limited ANSI color strictly for meaningful security finding severities
  and warning/error states when color is supported, with an automatic plain-text fallback.
- Safe stream writing for legacy Windows console encodings (cp437/cp1252/ascii) and
  Windows Virtual Terminal (VT100) mode activation on Windows 10/11 PowerShell & CMD.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any, Sequence, TextIO

from sentinel import __app_name__, __description__, __mode__, __scope__, __version__
from sentinel.utils.validation import sanitize_output_text

# Original compact 5-line pure-ASCII startup emblem for LINUY.
# Uses only standard 7-bit ASCII characters so it renders cleanly in both
# Windows PowerShell/Terminal and Linux terminals.
LINUY_ASCII_LOGO: tuple[str, ...] = (
    r"   _     ___ _   _ _   ___   __",
    r"  | |   |_ _| \ | | | | \ \ / /",
    r"  | |    | ||  \| | | | |\ V / ",
    r"  | |___ | || |\  | |_| | | |  ",
    r"  |_____|___|_| \_|\___/  |_|  ",
)

_WINDOWS_STD_OUTPUT_HANDLE = -11
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def safe_stream_write(stream: TextIO, text: str) -> None:
    """Write text to stream, degrading safely on legacy Windows/ASCII console encodings."""
    try:
        stream.write(text)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        safe_text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        stream.write(safe_text)
    stream.flush()


def _enable_windows_vt_mode() -> bool:
    """Enable ANSI Virtual Terminal sequences on Windows 10/11 consoles (CMD/PowerShell).

    Returns True if VT processing is supported/enabled, or False so output falls back
    cleanly to plain monochrome text instead of printing raw escape sequences.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = getattr(ctypes, "windll", None)
        if kernel32 is None or not hasattr(kernel32, "kernel32"):
            return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON"))
        k32 = kernel32.kernel32
        handle = k32.GetStdHandle(_WINDOWS_STD_OUTPUT_HANDLE)
        if handle in (0, -1, None):
            return False
        mode = ctypes.c_uint32()
        if k32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return bool(
                os.environ.get("WT_SESSION")
                or os.environ.get("ANSICON")
                or os.environ.get("TERM_PROGRAM")
            )
        if (mode.value & _ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0:
            return True
        if k32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0:
            return True
    except Exception:
        pass
    return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON"))


class TerminalStyle:
    """Manage restrained monochrome/gray typography and limited severity coloring."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    GREEN = "\033[32m"

    def __init__(self, use_color: bool | None = None) -> None:
        if use_color is None:
            self.use_color = self._detect_color_support()
        else:
            self.use_color = bool(use_color)

    @staticmethod
    def _detect_color_support() -> bool:
        if os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("TERM", "").lower() == "dumb":
            return False
        stream = getattr(sys, "stdout", None)
        if stream is None or not hasattr(stream, "isatty"):
            return False
        try:
            if not bool(stream.isatty()):
                return False
        except Exception:
            return False
        if os.name == "nt":
            return _enable_windows_vt_mode()
        return True

    def colorize(self, text: str, *codes: str) -> str:
        if not self.use_color or not codes:
            return text
        prefix = "".join(codes)
        return f"{prefix}{text}{self.RESET}"

    def format_status(self, status: str) -> str:
        """Format check status badges with restrained color only for findings/warnings/errors."""
        clean = sanitize_output_text(status, 24).upper()
        badge = f"[{clean}]"
        if clean == "PASS":
            return self.colorize(badge, self.BOLD)
        if clean in ("FINDING", "WARNING", "REVIEW"):
            return self.colorize(badge, self.YELLOW)
        if clean == "ERROR":
            return self.colorize(badge, self.RED)
        if clean == "UNSUPPORTED":
            return self.colorize(badge, self.DIM)
        return badge

    def format_severity(self, severity: str) -> str:
        """Reserve limited color for meaningful security finding severity levels."""
        clean = sanitize_output_text(severity, 24).upper()
        if clean == "CRITICAL":
            return self.colorize(clean, self.RED, self.BOLD)
        if clean == "HIGH":
            return self.colorize(clean, self.RED)
        if clean == "MEDIUM":
            return self.colorize(clean, self.YELLOW)
        if clean == "LOW":
            return clean
        if clean == "INFO":
            return self.colorize(clean, self.DIM)
        return clean

    def header(self, title: str) -> str:
        """Render a clean monochrome section header with subtle gray separator."""
        clean = sanitize_output_text(title, 120)
        line = "=" * len(clean)
        return f"{self.colorize(clean, self.BOLD)}\n{self.colorize(line, self.DIM)}"

    def section(self, title: str) -> str:
        """Render a clean subsection heading with subtle gray underline."""
        clean = sanitize_output_text(title, 120)
        line = "-" * len(clean)
        return f"\n{self.colorize(clean, self.BOLD)}\n{self.colorize(line, self.DIM)}"


def get_terminal_width(default: int = 100, minimum: int = 60, maximum: int = 160) -> int:
    """Return a bounded terminal column width for readable table layout."""
    try:
        cols = shutil.get_terminal_size((default, 24)).columns
    except Exception:
        cols = default
    return max(minimum, min(cols, maximum))


def format_startup_banner(
    platform_label: str,
    style: TerminalStyle | None = None,
    version: str | None = None,
) -> str:
    """Render the compact LINUY ASCII startup screen for the interactive shell.

    Uses strictly 7-bit ASCII characters so legacy Windows consoles (cp437/cp1252/ascii)
    never encounter UnicodeEncodeError.
    """
    st = style or TerminalStyle(use_color=False)
    clean_platform = sanitize_output_text(platform_label, 64)
    ver_str = sanitize_output_text(version or __version__, 24)
    rule = st.colorize("  " + ("-" * 62), st.DIM)

    logo_block = "\n".join(st.colorize(line, st.BOLD) for line in LINUY_ASCII_LOGO)
    title_line = f"  {st.colorize(__app_name__, st.BOLD)} v{ver_str} -- {__description__}"

    os_label = st.colorize("OS / Version  ", st.DIM)
    mode_label = st.colorize("Execution mode", st.DIM)
    scope_label = st.colorize("Scope         ", st.DIM)

    meta_block = (
        f"  {os_label} : {clean_platform}\n"
        f"  {mode_label} : {__mode__}\n"
        f"  {scope_label} : {__scope__}"
    )
    hint_line = "  Type 'help' to list available commands, or 'exit' to quit."

    return f"{logo_block}\n\n{title_line}\n{rule}\n{meta_block}\n{rule}\n{hint_line}\n"


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    max_width: int | None = None,
    max_col_width: int = 48,
) -> str:
    """Render a clean ASCII/Unicode-safe aligned table with control-character stripping."""
    if not headers:
        return ""

    term_width = max_width if max_width is not None else get_terminal_width()
    num_cols = len(headers)
    clean_headers = [sanitize_output_text(h, max_col_width) for h in headers]

    clean_rows: list[list[str]] = []
    for row in rows:
        padded = list(row)[:num_cols] + [""] * max(0, num_cols - len(row))
        clean_rows.append([sanitize_output_text(cell, max_col_width) for cell in padded])

    col_widths = [len(h) for h in clean_headers]
    for row in clean_rows:
        for idx, cell in enumerate(row):
            if len(cell) > col_widths[idx]:
                col_widths[idx] = len(cell)

    separator = "  "
    total_sep = len(separator) * (num_cols - 1)
    available_for_cols = max(num_cols * 8, term_width - total_sep)
    while sum(col_widths) > available_for_cols:
        widest_idx = max(range(num_cols), key=lambda i: col_widths[i])
        if col_widths[widest_idx] <= 8:
            break
        col_widths[widest_idx] -= 1

    def _fit(text: str, width: int) -> str:
        if len(text) > width:
            if width <= 3:
                return text[:width]
            return text[: width - 3] + "..."
        return text.ljust(width)

    header_line = separator.join(_fit(h, col_widths[i]) for i, h in enumerate(clean_headers))
    divider_line = separator.join("-" * col_widths[i] for i in range(num_cols))
    body_lines = [
        separator.join(_fit(cell, col_widths[i]) for i, cell in enumerate(row))
        for row in clean_rows
    ]

    if not body_lines:
        return f"{header_line}\n{divider_line}\n(no records)"
    return "\n".join([header_line, divider_line, *body_lines])


def format_kv_block(items: Sequence[tuple[str, Any]], indent: int = 2) -> str:
    """Format key-value pairs cleanly with aligned keys."""
    if not items:
        return ""
    clean_pairs = [
        (sanitize_output_text(k, 40), sanitize_output_text(v, 240)) for k, v in items
    ]
    key_width = max(len(k) for k, _ in clean_pairs)
    pad = " " * indent
    return "\n".join(f"{pad}{k.ljust(key_width)} : {v}" for k, v in clean_pairs)
