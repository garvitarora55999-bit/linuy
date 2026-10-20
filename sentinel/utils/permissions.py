"""Read-only permission and privilege inspection helpers.

Linux Sentinel never attempts privilege escalation, UAC bypass, or automatic
administrator/root relaunch. When a check requires higher privileges than the
current user holds, callers use these helpers to explain the limitation honestly.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Any


def get_current_username() -> str:
    """Return the current OS username safely without exposing environment secrets."""
    try:
        return getpass.getuser()
    except Exception:
        if hasattr(os, "getuid"):
            try:
                import pwd

                return pwd.getpwuid(os.getuid()).pw_name
            except Exception:
                return f"uid:{os.getuid()}"
        return "unknown"


def is_elevated() -> bool:
    """Return True if the current process has root (POSIX) or Administrator (Windows) rights."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except OSError:
            return False
    return False


def can_read_path(path: str | Path) -> tuple[bool, str]:
    """Check whether a file or directory can be read with current user permissions.

    Returns (readable, explanation).
    """
    target = Path(path)
    try:
        if not target.exists():
            return False, f"Path '{target}' does not exist on this system."
    except PermissionError:
        return False, f"Permission denied checking existence of '{target}'."
    except OSError as exc:
        return False, f"OS error inspecting '{target}': {exc.strerror or 'unknown error'}."

    if os.access(target, os.R_OK):
        return True, f"Readable by current user ({get_current_username()})."
    return False, f"Permission denied: '{target}' is not readable with current user privileges."


def get_execution_privilege_summary() -> dict[str, Any]:
    """Return a structured summary of current execution privileges and limitations."""
    elevated = is_elevated()
    username = get_current_username()
    uid = os.getuid() if hasattr(os, "getuid") else None
    euid = os.geteuid() if hasattr(os, "geteuid") else None

    if os.name == "nt":
        if elevated:
            limitation_note = (
                "Running with elevated Administrator privileges (read-only mode). "
                "Local Security Event Logs and all process paths should be accessible."
            )
        else:
            limitation_note = (
                "Running as standard Windows user (read-only mode). "
                "Live Windows Security Event Log (4624/4625) and elevated process paths "
                "require Administrator read access or an exported log file."
            )
    else:
        if elevated:
            limitation_note = (
                "Running as root (UID 0) in strict read-only mode. "
                "Protected configuration files (/etc/sudoers, /var/log/auth.log) and cross-user "
                "socket/process ownership are readable. Credential stores (/etc/shadow) are never read."
            )
        else:
            limitation_note = (
                "Running as unprivileged user in read-only mode. "
                "Checks requiring root read access (/etc/sudoers, cross-user socket PIDs, "
                "and restricted /var/log/auth.log) will report permission limitations honestly "
                "rather than guessing."
            )

    return {
        "username": username,
        "uid": uid,
        "euid": euid,
        "is_elevated": elevated,
        "privilege_level": "Elevated (Root/Admin)" if elevated else "Standard User",
        "execution_mode": "Read-only",
        "scope": "Local",
        "limitation_summary": limitation_note,
    }
