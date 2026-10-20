"""Console-script CLI entry point for LINUY ('linuy' and 'python -m sentinel')."""

from __future__ import annotations

from typing import Sequence

from sentinel.commands import main as _commands_main


def main(argv: Sequence[str] | None = None) -> int:
    """Run LINUY in direct CLI mode or launch the interactive shell."""
    return _commands_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
