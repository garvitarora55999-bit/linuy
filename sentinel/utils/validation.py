"""Input validation, path safety, output sanitization, and allowlisted subprocess execution.

All untrusted data (log files, CLI arguments, external tool output, process names,
and file paths) must pass through these helpers before rendering or serialization.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
from typing import Any, Sequence, TextIO

from sentinel import get_bundled_samples_dir, is_safe_report_directory_path

# Maximum allowed size for imported log files (10 MiB default).
DEFAULT_MAX_INPUT_BYTES: int = 10 * 1024 * 1024
# Maximum allowed size for reading system/proc configuration files (1 MiB default).
DEFAULT_MAX_SYSTEM_FILE_BYTES: int = 1 * 1024 * 1024
# Maximum allowed line length when reading untrusted log files.
DEFAULT_MAX_LINE_LENGTH: int = 4096
# Maximum number of lines processed from a single log file.
DEFAULT_MAX_LINES: int = 50_000
# Maximum bytes captured from an allowlisted external utility.
DEFAULT_MAX_SUBPROCESS_BYTES: int = 262_144

# Explicitly allowlisted read-only system inspection binaries.
# General-purpose scripting interpreters (powershell, pwsh, cmd, sh, bash, python)
# are intentionally excluded under least privilege.
ALLOWLISTED_BINARIES: frozenset[str] = frozenset(
    {
        # Linux / POSIX read-only utilities
        "who",
        "w",
        "last",
        "id",
        "getent",
        "ss",
        "netstat",
        # Windows read-only utilities
        "whoami",
        "net",
        "quser",
        "query",
        "tasklist",
        "wevtutil",
    }
)

# Trusted POSIX system binary directories (never user PATH).
POSIX_TRUSTED_BIN_DIRS: tuple[str, ...] = (
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
)

# Multi-call binary targets permitted when a root-owned symlink in a trusted bin dir points to them.
TRUSTED_MULTICALL_TARGETS: frozenset[str] = frozenset({"busybox", "toybox"})

# Hidden credential/secret directory names that user-supplied paths must never traverse.
FORBIDDEN_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        ".azure",
        ".docker",
    }
)

# Multi-segment directory sequences that store OS or cloud credentials.
FORBIDDEN_PATH_SEQUENCES: tuple[tuple[str, ...], ...] = (
    ("windows", "system32", "config"),
    (".config", "gcloud"),
)

# Restricted terminal filenames (checked on the target file's basename only, so
# user directories like /home/sam/... or C:\Users\sam\... remain valid).
FORBIDDEN_FILENAMES: frozenset[str] = frozenset(
    {
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "shadow",
        "gshadow",
        "master.passwd",
        ".env",
        "credentials",
        "login data",
        "cookies.sqlite",
        "key4.db",
        "ntuser.dat",
        "webcachev01.dat",
        "sam",
        "ntds.dit",
    }
)

# Windows reserved DOS device names (forbidden with or without extensions on all platforms).
WINDOWS_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "conin$",
        "conout$",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)

# Regex matching ANSI CSI / OSC / 7-bit escape sequences.
_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]"
)
# Regex matching Unicode bidirectional overrides/isolates and zero-width formatting characters.
_BIDI_AND_ZW_RE = re.compile(
    r"[\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)
# Regex matching ASCII and Unicode line/paragraph separators that must become spaces in single-line output.
_LINE_SEP_RE = re.compile(r"[\r\n\t\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")
# Regex matching remaining C0/C1 control characters.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0e-\x1b\x1f\x7f-\x9f]")
# Regex matching lone UTF-16 surrogates (\ud800-\udfff).
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
# Regex for splitting log files strictly on CRLF, LF, or CR (never on \u2028, \u2029, \x85, \x0b, \x0c).
_LOG_NEWLINE_SPLIT_RE = re.compile(r"\r\n|\n|\r")

# Regex patterns to redact accidental secret or credential strings in logs/errors.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|authorization)"
            r"(\s*[:=]\s*)([^\s,;\"']{3,128})"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(bearer)(\s+)([A-Za-z0-9._~+/=-]{8,256})"),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
)

# CSV formula injection prefixes per OWASP guidance.
_CSV_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True)
class CommandResult:
    """Structured result from an allowlisted read-only OS utility."""

    executable: str
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing_binary: bool = False
    permission_denied: bool = False
    output_truncated: bool = False
    error_message: str = ""

    @property
    def ok(self) -> bool:
        return (
            not self.timed_out
            and not self.missing_binary
            and not self.permission_denied
            and self.returncode == 0
        )


def sanitize_output_text(value: Any, max_len: int = 500) -> str:
    """Remove ANSI escapes, bidi overrides, zero-width chars, Unicode line separators, lone surrogates, and control chars."""
    if value is None:
        return ""
    text = str(value)
    text = _SURROGATE_RE.sub("\ufffd", text)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _BIDI_AND_ZW_RE.sub("", text)
    text = _LINE_SEP_RE.sub(" ", text)
    text = _CONTROL_CHAR_RE.sub("?", text)
    text = redact_sensitive_text(text)
    if max_len > 0 and len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def split_log_lines(raw_content: str) -> list[str]:
    """Split log text strictly on \\r\\n, \\n, or \\r so Unicode separators (\\u2028, \\u2029, \\x85) cannot forge lines."""
    if not raw_content:
        return []
    cleaned = _SURROGATE_RE.sub("\ufffd", raw_content)
    lines = _LOG_NEWLINE_SPLIT_RE.split(cleaned)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def redact_sensitive_text(text: str) -> str:
    """Mask common credential, token, or private key patterns in text."""
    if not text:
        return ""
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def sanitize_csv_cell(value: Any) -> str:
    """Sanitize a value for CSV export and neutralize formula injection prefixes."""
    if value is None:
        return ""
    # Check raw string first before control/whitespace normalization in case leading \t or \r was present
    raw_str = _SURROGATE_RE.sub("\ufffd", str(value))
    raw_starts_formula = raw_str.lstrip(" ").startswith(_CSV_FORMULA_PREFIXES) or raw_str.startswith(
        _CSV_FORMULA_PREFIXES
    )
    cleaned = sanitize_output_text(raw_str, max_len=2000)
    stripped = cleaned.lstrip(" ")
    if raw_starts_formula or stripped.startswith(_CSV_FORMULA_PREFIXES) or cleaned.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{cleaned}"
    return cleaned


def read_bounded_file(
    path: str | Path,
    max_bytes: int = DEFAULT_MAX_SYSTEM_FILE_BYTES,
    allow_symlinks: bool = False,
) -> str:
    """Read a local system or /proc file with a strict byte ceiling to prevent memory exhaustion."""
    target = Path(path)
    if not allow_symlinks and (target.is_symlink() or os.path.islink(target)):
        raise ValueError(f"Symbolic links are not permitted when reading {target.name}.")
    with target.open("rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        data = data[:max_bytes]
    text = data.decode("utf-8", errors="replace")
    return _SURROGATE_RE.sub("\ufffd", text)


def _reject_unc_device_and_ads_paths(raw_str: str) -> None:
    """Reject UNC network shares, Win32 device namespaces, reserved DOS devices, and NTFS ADS."""
    if raw_str.startswith("\\\\") or raw_str.startswith("//"):
        raise ValueError(
            "UNC network paths and Win32 device namespace paths are prohibited in local-only mode."
        )

    normalized_slashes = raw_str.replace("\\", "/")
    segments = [seg for seg in normalized_slashes.split("/") if seg]
    for idx, seg in enumerate(segments):
        if ":" in seg:
            if idx == 0 and re.fullmatch(r"[A-Za-z]:", seg):
                continue
            raise ValueError("NTFS Alternate Data Streams and colons in path segments are prohibited.")

        stem = seg.split(".", 1)[0].strip().lower()
        if stem in WINDOWS_RESERVED_DEVICE_NAMES:
            raise ValueError(f"Reserved operating-system device name '{seg}' is prohibited.")


def _check_forbidden_path_components(path_obj: Path) -> None:
    """Raise PermissionError if directory segments or terminal filename target restricted credential stores.

    Note: Checks FORBIDDEN_FILENAMES ('sam', 'shadow', etc.) strictly against path_obj.name
    so legitimate user home directories such as '/home/sam/...' or 'C:\\Users\\sam\\...' are allowed.
    """
    lower_parts = tuple(part.lower() for part in path_obj.parts)
    if set(lower_parts[:-1]) & FORBIDDEN_DIRECTORY_NAMES or (
        lower_parts and lower_parts[-1] in FORBIDDEN_DIRECTORY_NAMES
    ):
        raise PermissionError(
            "Access denied: path references a restricted credential or secret directory."
        )

    for seq in FORBIDDEN_PATH_SEQUENCES:
        seq_len = len(seq)
        for i in range(len(lower_parts) - seq_len + 1):
            if lower_parts[i : i + seq_len] == seq:
                raise PermissionError(
                    "Access denied: path references a restricted operating-system or cloud credential store."
                )

    filename_lower = path_obj.name.lower()
    if filename_lower in FORBIDDEN_FILENAMES:
        raise PermissionError(
            "Access denied: reading private keys, shadow/SAM files, or credential stores via --input is prohibited."
        )

    stem = filename_lower.split(".", 1)[0].strip()
    if stem in WINDOWS_RESERVED_DEVICE_NAMES:
        raise ValueError(f"Reserved operating-system device name '{path_obj.name}' is prohibited.")


def _walk_relative_without_symlinks(base_resolved: Path, rel_path: Path) -> Path:
    """Walk relative path segments from base_resolved, rejecting any symlink component."""
    current = base_resolved
    for part in rel_path.parts:
        if part in ("", "."):
            continue
        current = current / part
        if current.is_symlink() or os.path.islink(current):
            raise ValueError("Symbolic links are not permitted in input file paths.")
    return current


def validate_input_file(
    user_path: str | Path,
    max_size_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    base_dir: Path | None = None,
) -> Path:
    """Validate a user-supplied input file path for safe read-only log analysis."""
    if user_path is None:
        raise ValueError("Input file path cannot be empty.")
    raw_str = str(user_path).strip()
    if not raw_str:
        raise ValueError("Input file path cannot be empty.")
    if "\x00" in raw_str or "\n" in raw_str or "\r" in raw_str:
        raise ValueError("Input file path contains invalid control characters.")

    _reject_unc_device_and_ads_paths(raw_str)

    raw_candidate = Path(raw_str)
    _check_forbidden_path_components(raw_candidate)

    if not raw_candidate.is_absolute():
        candidate: Path | None = None
        if base_dir is not None:
            base_resolved = Path(base_dir).resolve(strict=True)
            cand_from_base = _walk_relative_without_symlinks(base_resolved, raw_candidate)
            if cand_from_base.exists() or cand_from_base.is_symlink():
                candidate = cand_from_base

        if candidate is None:
            cwd_resolved = Path.cwd().resolve(strict=True)
            cand_from_cwd = _walk_relative_without_symlinks(cwd_resolved, raw_candidate)
            if cand_from_cwd.exists() or cand_from_cwd.is_symlink():
                candidate = cand_from_cwd

        norm_rel_parts = [p for p in raw_str.replace("\\", "/").split("/") if p and p != "."]
        if candidate is None and len(norm_rel_parts) == 2 and norm_rel_parts[0].lower() == "samples":
            bundled_dir = get_bundled_samples_dir()
            if bundled_dir.is_dir():
                bundled_resolved = bundled_dir.resolve(strict=True)
                cand_bundled = _walk_relative_without_symlinks(bundled_resolved, Path(norm_rel_parts[1]))
                if cand_bundled.exists():
                    candidate = cand_bundled

        if candidate is None:
            fallback_base = (
                Path(base_dir).resolve(strict=True) if base_dir is not None else Path.cwd().resolve(strict=True)
            )
            candidate = _walk_relative_without_symlinks(fallback_base, raw_candidate)
    else:
        candidate = raw_candidate

    _check_forbidden_path_components(candidate)

    try:
        lstat_info = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Input file not found: {sanitize_output_text(raw_str, 120)}") from exc
    except PermissionError as exc:
        raise PermissionError(f"Permission denied inspecting input path: {exc.strerror or 'access denied'}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to inspect input file path safely: {exc.strerror or 'OS error'}") from exc

    if stat.S_ISLNK(lstat_info.st_mode):
        raise ValueError("Symbolic links are not permitted for input files.")

    if not stat.S_ISREG(lstat_info.st_mode):
        raise ValueError("Input path must be a regular file (not a directory, symlink, FIFO, or special device).")

    try:
        resolved = candidate.resolve(strict=True)
        resolved_lstat = os.lstat(resolved)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Input file not found: {sanitize_output_text(raw_str, 120)}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to resolve input file path safely: {exc.strerror or 'OS error'}") from exc

    if (resolved_lstat.st_dev, resolved_lstat.st_ino) != (lstat_info.st_dev, lstat_info.st_ino):
        raise ValueError("Symbolic link traversal is not permitted for input files.")

    _check_forbidden_path_components(resolved)

    if resolved_lstat.st_size > max_size_bytes:
        raise ValueError(
            f"Input file size ({resolved_lstat.st_size} bytes) exceeds maximum limit ({max_size_bytes} bytes)."
        )

    return resolved


def read_validated_input_file(
    user_path: str | Path,
    max_size_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    base_dir: Path | None = None,
) -> tuple[Path, str]:
    """Validate, atomically open without following symlinks, verify inode/fstat, and read bounded UTF-8 text."""
    resolved = validate_input_file(
        user_path=user_path,
        max_size_bytes=max_size_bytes,
        base_dir=base_dir,
    )
    pre_open_lstat = os.lstat(resolved)

    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(str(resolved), open_flags)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Input file not found: {resolved.name}") from exc
    except PermissionError as exc:
        raise PermissionError(f"Permission denied opening input file: {exc.strerror or 'access denied'}") from exc
    except OSError as exc:
        if exc.errno in (getattr(errno, "ELOOP", 40), getattr(errno, "EMLINK", 31)):
            raise ValueError("Symbolic links are not permitted for input files.") from exc
        raise ValueError(f"OS error opening input file: {exc.strerror or 'open failed'}") from exc

    with os.fdopen(fd, "rb") as fh:
        fd_stat = os.fstat(fh.fileno())
        if not stat.S_ISREG(fd_stat.st_mode):
            raise ValueError("Opened descriptor is not a regular file.")
        if (fd_stat.st_dev, fd_stat.st_ino) != (pre_open_lstat.st_dev, pre_open_lstat.st_ino):
            raise ValueError("File changed during open (potential symlink or race condition detected).")
        if fd_stat.st_size > max_size_bytes:
            raise ValueError(
                f"Input file size ({fd_stat.st_size} bytes) exceeds maximum limit ({max_size_bytes} bytes)."
            )

        chunks: list[bytes] = []
        total_read = 0
        chunk_size = min(65536, max_size_bytes + 1)
        while True:
            data = fh.read(chunk_size)
            if not data:
                break
            total_read += len(data)
            if total_read > max_size_bytes:
                raise ValueError(
                    f"Input file exceeded maximum size limit ({max_size_bytes} bytes) while reading."
                )
            chunks.append(data)

    raw_bytes = b"".join(chunks)
    decoded = raw_bytes.decode("utf-8", errors="replace")
    return resolved, _SURROGATE_RE.sub("\ufffd", decoded)


def validate_report_output_path(
    report_dir: Path,
    filename: str,
    allow_overwrite: bool = False,
) -> Path:
    """Validate that a report output path stays strictly within a safe, non-symlinked report directory."""
    if not filename or not filename.strip():
        raise ValueError("Report filename cannot be empty.")
    if "\x00" in filename or "\n" in filename or "\r" in filename:
        raise ValueError("Report filename contains invalid control characters.")

    if "/" in filename or "\\" in filename or ":" in filename or ".." in filename or Path(filename).name != filename:
        raise ValueError("Invalid report filename: path traversal and directory separators are prohibited.")

    if filename.startswith("."):
        raise ValueError("Report filename must not start with a dot ('.').")

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", filename):
        raise ValueError(
            "Report filename may only contain alphanumeric characters, dots, underscores, and hyphens."
        )

    stem = filename.split(".", 1)[0].strip().lower()
    if stem in WINDOWS_RESERVED_DEVICE_NAMES:
        raise ValueError(f"Reserved operating-system device name '{filename}' is prohibited.")

    report_dir_obj = Path(report_dir)
    if report_dir_obj.is_symlink() or os.path.islink(report_dir_obj):
        raise ValueError("Designated report directory must not be a symbolic link.")

    if not is_safe_report_directory_path(report_dir_obj):
        raise ValueError(
            "Designated report directory is not a permitted location (system, credential, and UNC directories are prohibited)."
        )

    report_dir_obj.mkdir(mode=0o700, parents=True, exist_ok=True)

    try:
        dir_lstat = os.lstat(report_dir_obj)
    except OSError as exc:
        raise ValueError(f"Cannot inspect report directory: {exc.strerror or 'OS error'}") from exc

    if stat.S_ISLNK(dir_lstat.st_mode) or not stat.S_ISDIR(dir_lstat.st_mode):
        raise ValueError("Designated report directory must be a real directory, not a symbolic link.")

    resolved_dir = report_dir_obj.resolve(strict=True)
    target = resolved_dir / filename

    if target.is_symlink() or os.path.islink(target):
        raise ValueError("Refusing to write to a symbolic link inside the report directory.")

    resolved_target = target.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_dir)
    except ValueError as exc:
        raise ValueError("Report output path escaped the designated report directory.") from exc

    if resolved_target.parent != resolved_dir:
        raise ValueError("Report output path must reside directly inside the designated report directory.")

    if resolved_target.exists() and not allow_overwrite:
        raise FileExistsError(f"Report file already exists and overwrite is disabled: {filename}")

    return resolved_target


def open_safe_report_writer(
    report_dir: Path,
    filename: str,
    allow_overwrite: bool = False,
) -> tuple[Path, TextIO]:
    """Validate and atomically open a report file inside report_dir without following symlinks."""
    target_path = validate_report_output_path(
        report_dir=report_dir,
        filename=filename,
        allow_overwrite=allow_overwrite,
    )

    dir_lstat = os.lstat(report_dir)
    if stat.S_ISLNK(dir_lstat.st_mode) or not stat.S_ISDIR(dir_lstat.st_mode):
        raise ValueError("Designated report directory was modified or replaced with a symbolic link.")

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | (os.O_TRUNC if allow_overwrite else os.O_EXCL)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(str(target_path), flags, 0o600)
    except FileExistsError as exc:
        if os.path.islink(target_path):
            raise ValueError("Refusing to write to a symbolic link inside the report directory.") from exc
        raise FileExistsError(f"Report file already exists and overwrite is disabled: {filename}") from exc
    except OSError as exc:
        if exc.errno in (getattr(errno, "ELOOP", 40), getattr(errno, "EMLINK", 31)):
            raise ValueError("Refusing to write to a symbolic link inside the report directory.") from exc
        if os.path.islink(target_path):
            raise ValueError("Refusing to write to a symbolic link inside the report directory.") from exc
        raise

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode):
            os.close(fd)
            raise ValueError("Report target is not a regular file.")
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        writer = os.fdopen(fd, "w", encoding="utf-8", newline="")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

    return target_path, writer


def _get_windows_trusted_dirs() -> list[Path]:
    """Return trusted Windows system binary directories derived from validated SystemRoot."""
    raw_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    raw_root = raw_root.strip()
    if (
        not raw_root
        or "\x00" in raw_root
        or ".." in raw_root
        or ";" in raw_root
        or raw_root.startswith("\\\\")
        or not re.match(r"^[A-Za-z]:[\\/]", raw_root)
    ):
        raw_root = r"C:\Windows"
    base = Path(raw_root)
    return [
        base / "System32",
        base / "System32" / "wbem",
    ]


def resolve_allowlisted_binary(
    binary_name: str,
    trusted_dirs: Sequence[str | Path] | None = None,
    require_root_owner: bool = True,
) -> str | None:
    """Locate an explicitly allowlisted system utility strictly from trusted system directories.

    Security controls:
    - Never uses shutil.which() or searches untrusted user PATH entries.
    - Rejects any binary name not in ALLOWLISTED_BINARIES or containing path separators.
    - Searches only platform-appropriate trusted directories (/usr/bin, /bin, /usr/sbin, /sbin
      on POSIX; SystemRoot\\System32 on Windows).
    - On POSIX, verifies that the directory, symlink (if any), resolved binary, and resolved
      parent directory are owned by root (UID 0) and not group- or world-writable.
    - Preserves the trusted symlink path (e.g. /bin/who -> /bin/busybox) when the target is
      a verified root-owned BusyBox/ToyBox multi-call binary so argv[0] applet dispatch works.
    """
    if not isinstance(binary_name, str) or not binary_name.strip():
        raise ValueError("Executable name cannot be empty.")

    raw = binary_name.strip()
    if "/" in raw or "\\" in raw or ".." in raw or ":" in raw or "\x00" in raw:
        raise ValueError(f"Executable '{binary_name}' must be a bare allowlisted command name, not a path.")

    normalized = raw.lower()
    if normalized.endswith(".exe"):
        normalized = normalized[:-4]
    if normalized not in ALLOWLISTED_BINARIES:
        raise ValueError(f"Executable '{binary_name}' is not in the security allowlist.")

    if trusted_dirs is not None:
        search_dirs = [Path(d) for d in trusted_dirs]
    elif os.name == "nt":
        search_dirs = _get_windows_trusted_dirs()
    else:
        search_dirs = [Path(d) for d in POSIX_TRUSTED_BIN_DIRS]

    exe_filename = f"{normalized}.exe" if os.name == "nt" else normalized

    for directory in search_dirs:
        try:
            if not directory.exists() or not directory.is_dir():
                continue
            if os.name == "nt" and directory.is_symlink():
                continue
            resolved_dir = directory.resolve(strict=True)
            dir_stat = resolved_dir.stat()
            if os.name != "nt":
                dir_mode = stat.S_IMODE(dir_stat.st_mode)
                if (dir_mode & stat.S_IWOTH) or (dir_mode & stat.S_IWGRP):
                    continue
                if require_root_owner and dir_stat.st_uid != 0:
                    continue

            candidate = resolved_dir / exe_filename
            if not candidate.exists():
                continue
            cand_lstat = os.lstat(candidate)
            if os.name == "nt":
                if stat.S_ISLNK(cand_lstat.st_mode) or candidate.is_symlink():
                    continue
            else:
                if stat.S_ISLNK(cand_lstat.st_mode) and require_root_owner and cand_lstat.st_uid != 0:
                    continue

            resolved_bin = candidate.resolve(strict=True)
            if not resolved_bin.is_file() or not os.access(resolved_bin, os.X_OK):
                continue

            bin_stat = resolved_bin.stat()
            if not stat.S_ISREG(bin_stat.st_mode):
                continue

            if os.name == "nt":
                try:
                    resolved_bin.relative_to(resolved_dir)
                except ValueError:
                    continue
                return str(resolved_bin)

            bin_mode = stat.S_IMODE(bin_stat.st_mode)
            parent_stat = resolved_bin.parent.stat()
            parent_mode = stat.S_IMODE(parent_stat.st_mode)
            if (bin_mode & stat.S_IWOTH) or (bin_mode & stat.S_IWGRP):
                continue
            if (parent_mode & stat.S_IWOTH) or (parent_mode & stat.S_IWGRP):
                continue
            if require_root_owner and (bin_stat.st_uid != 0 or parent_stat.st_uid != 0):
                continue

            # Support BusyBox / ToyBox multi-call binaries where /bin/who is a root-owned
            # symlink pointing to /bin/busybox and requires argv[0] to be the applet path.
            if stat.S_ISLNK(cand_lstat.st_mode):
                target_name = resolved_bin.name.lower()
                if target_name in TRUSTED_MULTICALL_TARGETS:
                    return str(candidate)
                if target_name != exe_filename and not target_name.startswith(f"{normalized}."):
                    continue

            return str(resolved_bin)
        except OSError:
            continue

    return None


def _build_safe_subprocess_env() -> dict[str, str]:
    """Construct a minimal, clean environment for allowlisted read-only child processes."""
    if os.name == "nt":
        sys_root = os.environ.get("SystemRoot") or r"C:\Windows"
        if (
            "\x00" in sys_root
            or ".." in sys_root
            or sys_root.startswith("\\\\")
            or not re.match(r"^[A-Za-z]:[\\/]", sys_root)
        ):
            sys_root = r"C:\Windows"
        return {
            "SystemRoot": sys_root,
            "WINDIR": sys_root,
            "PATH": f"{sys_root}\\System32;{sys_root}\\System32\\wbem",
        }
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LANG": "C",
    }


def _read_stream_bounded(
    stream: Any,
    max_bytes: int,
    sink: list[bytes],
    overflow_flag: list[bool],
) -> None:
    """Read from a subprocess pipe up to max_bytes while draining excess output safely."""
    total = 0
    chunk_size = min(8192, max(1024, max_bytes))
    try:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            if total < max_bytes:
                remaining = max_bytes - total
                if len(chunk) <= remaining:
                    sink.append(chunk)
                    total += len(chunk)
                else:
                    sink.append(chunk[:remaining])
                    total = max_bytes
                    overflow_flag[0] = True
            else:
                overflow_flag[0] = True
                # Drain up to 1 MiB total to avoid deadlocking short commands, then stop reading
                total += len(chunk)
                if total > max_bytes + (1024 * 1024):
                    break
    except OSError:
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def run_allowlisted_command(
    binary_name: str,
    args: Sequence[str] = (),
    timeout: float = 5.0,
    max_output_bytes: int = DEFAULT_MAX_SUBPROCESS_BYTES,
    trusted_dirs: Sequence[str | Path] | None = None,
) -> CommandResult:
    """Execute a fixed, allowlisted read-only OS inspection utility without a shell.

    Security controls:
    - Rejects any binary not in ALLOWLISTED_BINARIES.
    - Resolves executable strictly from trusted system directories (never user PATH).
    - Validates every argument is a plain string without null or newline bytes.
    - Uses subprocess.Popen with shell=False, stdin=DEVNULL, and bounded streaming
      output collection so child output cannot exhaust memory before truncation.
    - Enforces a strict execution timeout and terminates/kills hung child processes.
    """
    normalized = binary_name.strip().lower()
    if normalized.endswith(".exe"):
        normalized = normalized[:-4]
    if normalized not in ALLOWLISTED_BINARIES:
        raise ValueError(f"Disallowed command '{binary_name}': not in ALLOWLISTED_BINARIES.")

    clean_args: list[str] = []
    for arg in args:
        if not isinstance(arg, str):
            raise TypeError("All command arguments must be strings.")
        if "\x00" in arg or "\n" in arg or "\r" in arg:
            raise ValueError("Command argument contains prohibited control characters.")
        clean_args.append(arg)

    executable = resolve_allowlisted_binary(normalized, trusted_dirs=trusted_dirs)
    if not executable:
        return CommandResult(
            executable=normalized,
            args=tuple(clean_args),
            returncode=127,
            stdout="",
            stderr="",
            missing_binary=True,
            error_message=f"Required utility '{normalized}' is not installed in trusted system directories.",
        )

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_overflow = [False]
    stderr_overflow = [False]
    proc: subprocess.Popen[bytes] | None = None

    try:
        proc = subprocess.Popen(
            [executable, *clean_args],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=_build_safe_subprocess_env(),
        )
        t_out = threading.Thread(
            target=_read_stream_bounded,
            args=(proc.stdout, max_output_bytes, stdout_chunks, stdout_overflow),
            daemon=True,
        )
        t_err = threading.Thread(
            target=_read_stream_bounded,
            args=(proc.stderr, max_output_bytes, stderr_chunks, stderr_overflow),
            daemon=True,
        )
        t_out.start()
        t_err.start()

        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=2.0)
            except (OSError, subprocess.SubprocessError):
                pass
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            return CommandResult(
                executable=executable,
                args=tuple(clean_args),
                returncode=124,
                stdout="",
                stderr="",
                timed_out=True,
                error_message=f"Command '{normalized}' timed out after {timeout:.1f}s.",
            )

        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

    except PermissionError as exc:
        return CommandResult(
            executable=executable,
            args=tuple(clean_args),
            returncode=126,
            stdout="",
            stderr="",
            permission_denied=True,
            error_message=f"Permission denied executing '{normalized}': {exc.strerror or 'access denied'}.",
        )
    except OSError as exc:
        return CommandResult(
            executable=executable,
            args=tuple(clean_args),
            returncode=1,
            stdout="",
            stderr="",
            error_message=f"OS error executing '{normalized}': {exc.strerror or 'execution error'}.",
        )
    finally:
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except (OSError, subprocess.SubprocessError):
                    pass
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    raw_stdout = b"".join(stdout_chunks)[:max_output_bytes]
    raw_stderr = b"".join(stderr_chunks)[:max_output_bytes]
    stdout_str = _SURROGATE_RE.sub("\ufffd", raw_stdout.decode("utf-8", errors="replace"))
    stderr_str = _SURROGATE_RE.sub("\ufffd", raw_stderr.decode("utf-8", errors="replace"))
    was_truncated = stdout_overflow[0] or stderr_overflow[0]

    lower_err = (stderr_str + " " + stdout_str).lower()
    perm_denied = returncode != 0 and any(
        phrase in lower_err
        for phrase in ("access is denied", "permission denied", "operation not permitted", "requires elevation")
    )

    return CommandResult(
        executable=executable,
        args=tuple(clean_args),
        returncode=returncode,
        stdout=stdout_str,
        stderr=stderr_str,
        permission_denied=perm_denied,
        output_truncated=was_truncated,
        error_message=sanitize_output_text(stderr_str.strip(), 240) if returncode != 0 else "",
    )
