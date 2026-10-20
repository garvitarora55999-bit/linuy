"""LINUY package metadata and cross-platform path resolution helpers."""

from __future__ import annotations

import os
from pathlib import Path
import re

__app_name__ = "LINUY"
__version__ = "1.0.0"
__description__ = "Cross-platform defensive security inspection CLI"
__mode__ = "Read-only"
__scope__ = "Local"

PACKAGE_DIR: Path = Path(__file__).resolve().parent

_FORBIDDEN_REPORT_DIR_PREFIXES_POSIX: tuple[str, ...] = (
    "/etc",
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib64",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/run/systemd",
)

_FORBIDDEN_REPORT_DIR_SEGMENTS: frozenset[str] = frozenset(
    {".ssh", ".gnupg", ".aws", ".kube", ".azure", ".docker"}
)


def is_safe_report_directory_path(candidate: Path | str) -> bool:
    """Return True if candidate is a safe local directory path for storing reports."""
    raw = str(candidate).strip()
    if not raw or "\x00" in raw or "\n" in raw or "\r" in raw:
        return False
    if raw.startswith("\\\\") or raw.startswith("//"):
        return False

    cand_obj = Path(raw)
    if ".." in cand_obj.parts:
        return False

    is_win_abs = bool(re.match(r"^[A-Za-z]:[\\/]", raw))
    if not cand_obj.is_absolute() and not is_win_abs:
        return False

    norm_posix = raw.replace("\\", "/")
    segments = [s for s in norm_posix.split("/") if s]
    lower_parts = {s.lower() for s in segments}
    if lower_parts & _FORBIDDEN_REPORT_DIR_SEGMENTS:
        return False

    for idx, seg in enumerate(segments):
        if ":" in seg and not (idx == 0 and re.fullmatch(r"[A-Za-z]:", seg)):
            return False

    if is_win_abs:
        lower_win = norm_posix.lower().rstrip("/")
        for win_forbid in (
            "c:/windows",
            "c:/program files",
            "c:/program files (x86)",
            "c:/system volume information",
        ):
            if lower_win == win_forbid or lower_win.startswith(win_forbid + "/"):
                return False
        if re.fullmatch(r"[a-z]:", lower_win):
            return False
        return True

    try:
        resolved_str = str(cand_obj.resolve(strict=False)).replace("\\", "/")
    except OSError:
        return False

    for prefix in _FORBIDDEN_REPORT_DIR_PREFIXES_POSIX:
        if resolved_str == prefix or resolved_str.startswith(prefix + "/"):
            return False
    if resolved_str == "/":
        return False

    return True


def is_installed_in_site_packages(path: Path | None = None) -> bool:
    """Return True if the package resides inside site-packages or dist-packages."""
    target = path or PACKAGE_DIR
    lower_parts = {p.lower() for p in target.parts}
    return bool(lower_parts & {"site-packages", "dist-packages"})


def get_source_checkout_root() -> Path | None:
    """Return the repository root if running from a source checkout, else None."""
    parent = PACKAGE_DIR.parent
    if is_installed_in_site_packages(PACKAGE_DIR):
        return None
    if (parent / "sentinel.py").is_file() or (parent / "pyproject.toml").is_file():
        return parent
    return None


def get_bundled_samples_dir() -> Path:
    """Return the path to bundled sample authentication log fixtures."""
    pkg_samples = PACKAGE_DIR / "samples"
    if pkg_samples.is_dir():
        return pkg_samples
    checkout_samples = PACKAGE_DIR.parent / "samples"
    return checkout_samples


def get_user_data_report_dir() -> Path:
    """Return an OS-appropriate user-local report directory when installed as a package."""
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
        if local_app_data and "\x00" not in local_app_data and Path(local_app_data).is_absolute():
            base = Path(local_app_data)
        else:
            base = Path.home() / "AppData" / "Local"
        return base / "linuy" / "reports"

    xdg_state = os.environ.get("XDG_STATE_HOME", "").strip()
    if xdg_state and "\x00" not in xdg_state and Path(xdg_state).is_absolute():
        base = Path(xdg_state)
    else:
        base = Path.home() / ".local" / "state"
    return base / "linuy" / "reports"


def resolve_default_report_dir(project_root: Path | None = None) -> Path:
    """Resolve the safe designated report directory for both source checkouts and installed packages."""
    env_override = os.environ.get("LINUY_REPORT_DIR", "").strip()
    if env_override:
        cand = Path(env_override).expanduser()
        if cand.is_absolute() and is_safe_report_directory_path(cand) and not cand.is_symlink():
            return cand

    if project_root is not None:
        root_obj = Path(project_root)
        if not is_installed_in_site_packages(root_obj):
            return root_obj / "reports"

    checkout_root = get_source_checkout_root()
    if checkout_root is not None:
        candidate_reports = checkout_root / "reports"
        if candidate_reports.is_dir() and os.access(candidate_reports, os.W_OK | os.X_OK):
            return candidate_reports
        if os.access(checkout_root, os.W_OK | os.X_OK):
            return candidate_reports

    return get_user_data_report_dir()
