#!/usr/bin/env python3
"""LINUY — Cross-Platform Read-Only Defensive Security Inspection CLI.

Entry point supporting both:
1. Interactive shell mode (`python sentinel.py` or installed `linuy`)
2. Direct CLI execution (`python sentinel.py system`, `linuy audit`, etc.)
"""

from __future__ import annotations

from typing import Sequence

from sentinel.commands import main as _cli_main


def main(argv: Sequence[str] | None = None) -> int:
    """Delegate execution to sentinel.commands.main."""
    return _cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
