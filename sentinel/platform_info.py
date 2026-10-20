"""Cross-platform operating system, distribution, and utility detection.

Provides accurate platform metadata for Windows 10/11, Kali Linux, Ubuntu,
Debian, and other Linux distributions without executing untrusted shells.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import socket
import sys
from typing import Any

from sentinel.utils.permissions import get_execution_privilege_summary
from sentinel.utils.validation import (
    read_bounded_file,
    resolve_allowlisted_binary,
    sanitize_output_text,
)


@dataclass(frozen=True)
class PlatformProfile:
    """Normalized description of the current operating system and runtime environment."""

    os_family: str  # "Linux", "Windows", "Darwin", or "Other"
    distro_name: str  # e.g., "Debian GNU/Linux 12", "Kali GNU/Linux", "Windows 11"
    distro_id: str  # e.g., "debian", "kali", "ubuntu", "windows"
    os_release: str
    os_version: str
    architecture: str
    hostname: str
    python_version: str
    python_Supported: bool
    psutil_available: bool
    psutil_version: str
    available_utilities: tuple[str, ...]
    missing_utilities: tuple[str, ...]
    supported_features: tuple[str, ...]
    unsupported_features: tuple[str, ...]
    privilege_summary: dict[str, Any]

    @property
    def display_label(self) -> str:
        """Compact label suitable for the startup banner and reports."""
        if self.os_family in ("Linux", "Windows"):
            return self.distro_name
        return f"{self.os_family} ({self.os_release})"


def parse_os_release(os_release_path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Parse /etc/os-release safely as bounded key=value data without executing it."""
    result: dict[str, str] = {}
    try:
        if not os_release_path.is_file():
            return result
        # Note: /etc/os-release is standardly a symlink to /usr/lib/os-release on Debian/Ubuntu/Kali.
        content = read_bounded_file(os_release_path, max_bytes=65536, allow_symlinks=True)
        for line in content.splitlines()[:100]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, val = stripped.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key:
                result[key] = sanitize_output_text(val, 120)
    except (OSError, ValueError):
        return {}
    return result


def check_psutil_status() -> tuple[bool, str]:
    """Check whether psutil is importable and return (available, version_string)."""
    try:
        import psutil  # type: ignore

        ver = getattr(psutil, "__version__", "installed")
        return True, str(ver)
    except ImportError:
        return False, "not installed (using native stdlib/OS fallback)"


def detect_platform(
    system_override: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
) -> PlatformProfile:
    """Inspect current platform, available utilities, and supported features."""
    raw_sys = (system_override or platform.system() or "Unknown").strip()
    sys_lower = raw_sys.lower()

    if sys_lower == "linux":
        os_family = "Linux"
    elif sys_lower == "windows":
        os_family = "Windows"
    elif sys_lower == "darwin":
        os_family = "Darwin"
    else:
        os_family = "Other"

    os_rel = sanitize_output_text(platform.release(), 80)
    os_ver = sanitize_output_text(platform.version(), 120)
    arch = sanitize_output_text(platform.machine() or "unknown", 40)

    try:
        hostname = sanitize_output_text(socket.gethostname(), 80)
    except Exception:
        hostname = "localhost"

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_supported = (sys.version_info.major, sys.version_info.minor) >= (3, 10)
    psutil_ok, psutil_ver = check_psutil_status()

    if os_family == "Linux":
        os_data = parse_os_release(os_release_path)
        distro_name = os_data.get("PRETTY_NAME") or os_data.get("NAME") or f"Linux {os_rel}"
        distro_id = (os_data.get("ID") or "linux").lower()
        candidate_utils = ("who", "w", "last", "id", "getent", "ss", "netstat")
        supported_features = (
            "system",
            "doctor",
            "audit (Linux filesystem, SSH, sysctl, sudoers, PATH checks)",
            "network (psutil or /proc/net + ss read-only socket inspection)",
            "processes (psutil or /proc read-only process enumeration)",
            "users (local /etc/passwd accounts, active sessions, sudo/wheel/UID 0 admins)",
            "auth (imported JSONL/JSON/syslog auth.log & optional local /var/log/auth.log)",
            "report (JSON and CSV export with CSV formula-injection defense)",
        )
        unsupported_features = (
            "Windows Registry/Defender/EventLog live checks (not applicable on Linux)",
        )
    elif os_family == "Windows":
        try:
            win_rel, win_ver, _, _ = platform.win32_ver()
            build_num = 0
            if win_ver:
                parts = win_ver.split(".")
                if len(parts) >= 3 and parts[2].isdigit():
                    build_num = int(parts[2])
            if build_num >= 22000:
                distro_name = f"Windows 11 (Build {build_num})"
            elif win_rel:
                distro_name = f"Windows {win_rel} ({win_ver})" if win_ver else f"Windows {win_rel}"
            else:
                distro_name = f"Windows ({os_rel})"
        except Exception:
            distro_name = f"Windows {os_rel}".strip()
        distro_id = "windows"
        candidate_utils = ("whoami", "net", "quser", "query", "tasklist", "netstat", "wevtutil")
        supported_features = (
            "system",
            "doctor",
            "audit (Windows UAC registry and PATH checks)",
            "network (psutil or netstat read-only endpoint inspection)",
            "processes (psutil or tasklist read-only process enumeration)",
            "users (local accounts, active sessions via psutil/quser, local Administrators)",
            "auth (imported JSONL/JSON Windows Event 4624/4625 & syslog logs)",
            "report (JSON and CSV export with CSV formula-injection defense)",
        )
        unsupported_features = (
            "Linux /etc/passwd, /etc/shadow, and /proc/sys kernel checks (not applicable on Windows)",
        )
    else:
        distro_name = f"{raw_sys} {os_rel}".strip()
        distro_id = sys_lower
        candidate_utils = ("who", "id", "netstat")
        supported_features = (
            "system",
            "doctor",
            "auth (imported log files)",
            "report (JSON and CSV export)",
        )
        unsupported_features = (
            "Native Windows and Linux platform-specific host audits",
        )

    avail_utils: list[str] = []
    missing_utils: list[str] = []
    for util_name in candidate_utils:
        try:
            resolved = resolve_allowlisted_binary(util_name)
        except ValueError:
            resolved = None
        if resolved:
            avail_utils.append(util_name)
        else:
            missing_utils.append(util_name)

    priv_summary = get_execution_privilege_summary()

    return PlatformProfile(
        os_family=os_family,
        distro_name=sanitize_output_text(distro_name, 80),
        distro_id=sanitize_output_text(distro_id, 40),
        os_release=os_rel,
        os_version=os_ver,
        architecture=arch,
        hostname=hostname,
        python_version=py_ver,
        python_Supported=py_supported,
        psutil_available=psutil_ok,
        psutil_version=psutil_ver,
        available_utilities=tuple(avail_utils),
        missing_utilities=tuple(missing_utils),
        supported_features=supported_features,
        unsupported_features=unsupported_features,
        privilege_summary=priv_summary,
    )
