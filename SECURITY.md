# Security Policy, Threat Model & Audit Log — LINUY

## 1. Supported Project Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Current active cross-platform read-only release (Python 3.10+) |
| `< 1.0.0` | No | Pre-release prototypes are unsupported |

## 2. Reporting a Suspected Vulnerability Responsibly

If you discover a security weakness, path traversal flaw, command injection vector, parser denial-of-service, or unintended data exposure in LINUY:

1. **Do not publish working exploit details, private logs, or sensitive host information in public GitHub issues.**
2. Submit a private vulnerability report via the repository's private security advisory channel (or contact the maintainer directly as listed in the repository profile).
3. Include the following details in your report:
   - **Affected version / commit hash** and Python version (`python --version`).
   - **Operating system and edition** (e.g., Windows 11, Kali Linux, Ubuntu 24.04, Debian 12).
   - **Component or command affected** (e.g., `auth --input`, `report --format csv`, `sentinel/utils/validation.py`).
   - **Minimal reproduction steps** using synthetic, non-sensitive input data.
   - **Observed vs. expected behavior** and potential security impact.

*Note on response expectations:* LINUY is an independent open-source project maintained on a best-effort basis. While reports are reviewed seriously, no formal SLA, bounty, or guaranteed turnaround time is promised.

## 3. Threat Model

### 3.1 Assets to Protect
- **Host Confidentiality & Credentials**: Password hashes (`/etc/shadow`, SAM), SSH private keys (`.ssh/id_*`), cloud/container credentials (`.aws`, `.azure`, `.kube`, `.docker`, `gcloud`), API tokens, NetNTLMv2 hashes (preventing outbound SMB connections), process environment variables (`/proc/<pid>/environ`), and command-line arguments (`/proc/<pid>/cmdline`).
- **Host Integrity**: System configuration files, user accounts, running processes, firewall state, and arbitrary user files outside the designated report directory.
- **Operator Terminal & Workstation**: The analyst's terminal emulator (protecting against malicious ANSI escape sequences, bidirectional overrides, zero-width characters, lone surrogates, and Unicode line-separator log forging) and spreadsheet software used to open exported CSV reports (protecting against CSV formula injection).
- **Host Availability**: Local CPU and memory resources when parsing untrusted, malformed, deeply nested, or high-volume authentication log files and collecting subprocess or system file output.

### 3.2 Trust Boundaries
1. **Interactive CLI Input & Direct CLI Arguments**: Untrusted until tokenized and validated by `argparse` (`_SafeArgumentParser`).
2. **Imported Log Files (`auth --input <file>`)**: Completely untrusted data. An analyst may download and analyze a log file crafted by an adversary.
3. **User `PATH` and Environment Variables**: Treated as untrusted for binary resolution; allowlisted OS utilities are resolved exclusively from fixed trusted system directories, and `LINUY_REPORT_DIR` is validated against system, credential, relative, and UNC paths.
4. **Local OS State & External Utility Output**: Process names, usernames, hostnames, cached findings, and socket banners read from `/proc` or OS utilities may be influenced by unprivileged local users or remote clients.
5. **Filesystem Report Output (`reports/` or user state dir)**: Write operations must never cross outside the resolved report directory boundary, follow symbolic links, or leave partial/corrupted files behind on failure.

### 3.3 Mitigations & Remediations Implemented
- **No Arbitrary Command Execution**: `eval()`, `exec()`, and `shell=True` are strictly prohibited across the entire codebase. Unknown commands typed into `linuy >` return an error and never fall through to the OS shell.
- **Least-Privilege Trusted-Directory Subprocess Resolution & BusyBox Support**: `resolve_allowlisted_binary()` in `sentinel/utils/validation.py` never uses `shutil.which()` or `os.environ["PATH"]`. General-purpose scripting interpreters (`powershell`, `pwsh`, `cmd`, `bash`, `sh`, `python`) are excluded from `ALLOWLISTED_BINARIES`. Allowlisted binaries are resolved strictly from `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin` on POSIX (verifying root ownership `st_uid == 0` and absence of group/world write bits on the directory, symlink, target binary, and target parent directory) and validated `SystemRoot\System32` on Windows. Root-owned symlinks pointing to verified `busybox`/`toybox`/`kmod` multi-call binaries preserve the applet symlink path as `argv[0]`.
- **Streaming Bounded Subprocess Execution**: `run_allowlisted_command()` uses `subprocess.Popen` with `shell=False`, `stdin=subprocess.DEVNULL`, a sanitized environment, execution timeouts (`proc.kill()` on timeout), and streaming reader threads (`_read_stream_bounded`) that enforce `max_output_bytes` during collection so a verbose child process cannot exhaust memory before truncation.
- **Linear-Time `O(N)` Authentication Anomaly Detection**: `detect_auth_anomalies()` in `sentinel/checks/authentication.py` uses a two-pointer sliding window (`left_idx` over `failure_epochs` and `failures_list`), analyzing 20,000 failed-login events in ~0.04s and 50,000 events in ~0.11s while preserving exact detection semantics for `AUTH-DET-001` and `AUTH-DET-002`.
- **Numeric, Timestamp, PAM, and Syslog Year Hardening**:
  - Rejects `bool` and non-finite `float` values (`Infinity`, `-Infinity`, `NaN`) in `EventID` and timestamps, and catches `OverflowError` on extreme `int()` and `datetime.astimezone()` / `.timestamp()` conversions near `datetime.min` and `datetime.max`.
  - Extracts `rhost` and `user` from PAM authentication failure lines (`pam_unix`, `pam_sss`, etc.) regardless of field spacing so PAM failures are normalized and reach `AUTH-DET-001` / `AUTH-DET-002`.
  - Infers RFC-3164 syslog years dynamically from `reference_time` (defaulting to current UTC time) rather than hardcoding a year, rolling back one year across Jan 1 year boundaries instead of inventing future dates, and handling leap/non-leap `Feb 29` and invalid calendar dates safely.
- **Path Validation Without False Positives on User Directories**: `_check_forbidden_path_components()` separates `FORBIDDEN_DIRECTORY_NAMES` (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.azure`, `.docker`) and `FORBIDDEN_PATH_SEQUENCES` (`windows/system32/config`, `.config/gcloud`) from terminal `FORBIDDEN_FILENAMES` (`sam`, `shadow`, `id_rsa`, etc.), permitting legitimate user paths such as `/home/sam/...` or `C:\Users\sam\...` while blocking `/etc/shadow` and `C:\Windows\System32\config\SAM`.
- **Anti-Log-Forging & Terminal Output Sanitization**: `split_log_lines()` splits strictly on `\r\n|\n|\r` so Unicode line separators (`\u2028`, `\u2029`, `\x85`, `\x0b`, `\x0c`, `\x1c`–`\x1e`) cannot forge extra log records. `sanitize_output_text()` strips ANSI CSI/OSC escape sequences, C0/C1 control characters, Unicode bidirectional overrides/isolates (`\u061c`, `\u200e`, `\u200f`, `\u202a`–`\u202e`, `\u2066`–`\u2069`), zero-width characters (`\u00ad`, `\u200b`–`\u200d`, `\u2060`, `\ufeff`), and lone UTF-16 surrogates (`\ud800`–`\udfff`), and redacts common secret patterns.
- **Findings Cache Ownership Validation & Atomic Report Cleanup**: `FindingStore._load_cache()` verifies on POSIX that both the report directory and `.last_run_cache.json` are owned by `os.geteuid()`, the directory is not group/world-writable (`mode & 0o022 == 0`), and the cache file has no group/world permissions (`mode & 0o077 == 0`). `export_findings_report()` pre-renders report content in memory and unlinks the target file if any write error occurs so empty or misleading report files are never left behind.
- **Zero Runtime Assertions & Legacy Console / Pipe Compatibility**: All runtime validation uses explicit conditional checks rather than `assert` statements so behavior is identical under `python -O`. The startup banner uses pure 7-bit ASCII, `safe_stream_write()` handles legacy Windows console encodings (`cp437`/`cp1252`/`ascii`), and `BrokenPipeError` is handled cleanly when piping output to `head`.

## 4. Static Analysis (Bandit) & Dependency Audit Notes

- **Bandit Static Analysis Review**:
  - **`B101` (`assert_used`)**: Eliminated across all application and test modules; zero `assert` statements exist in `sentinel/`.
  - **`B404` / `B603` (`import_subprocess` / `subprocess_without_shell_equals_true`)**: Confined to `sentinel/utils/validation.py` (`run_allowlisted_command`), which enforces `shell=False`, a strict binary name allowlist (`ALLOWLISTED_BINARIES`), trusted system directory resolution (`resolve_allowlisted_binary`), argument control-character rejection, `stdin=subprocess.DEVNULL`, and bounded streaming output threads.
  - **`B105` (`hardcoded_password_string`) & `shell` attribute heuristics**: Enum constant `FindingStatus.PASS = "PASS"` in `sentinel/findings.py`, registry path constant `key_path` in `sentinel/checks/windows.py`, and dataclass field `shell: str` on `LinuxUserRecord` / `LinuxAdminRecord` (representing a POSIX login shell path from `/etc/passwd`) are benign identifiers, not credentials or shell invocations.
- **Dependency Audit & Version Constraints**:
  - **`psutil>=5.9.8,<7.0.0`**: Retained as the sole runtime dependency in `pyproject.toml` and `requirements.txt`. `>=5.9.8` provides pre-built wheels for Python 3.10–3.13 across Linux and Windows, while `<7.0.0` guards against unverified breaking API changes in a future major release.
  - **`pytest` (`PYSEC-2026-1845` / `CVE-2025-71176`)**: `pytest` through `9.0.2` on UNIX uses predictable `/tmp/pytest-of-{user}` directory names in its `tmpdir`/`tmp_path` fixtures. `pytest` has been removed from `requirements.txt` (it is not required at runtime), and all 50 tests in `tests/` use Python's standard library `unittest` and `tempfile.TemporaryDirectory()` (which creates cryptographically random `0700` directories via `tempfile.mkdtemp()`). If running `pytest` manually on shared UNIX hosts, pass `pytest --basetemp=$HOME/.cache/pytest-tmp`.

## 5. Remaining Risks & Platform Limitations

No software can be guaranteed vulnerability-free. Remaining known risks and platform limitations are classified below:

- **Critical**: None identified.
- **High**: None identified.
- **Medium**:
  - **Windows Pre-Open Symlink TOCTOU & ACL Inspection**: On POSIX, `os.O_NOFOLLOW` is enforced atomically by the kernel inside `os.open()`, and `resolve_allowlisted_binary()` verifies `st_uid == 0` and mode bits. On Windows, the CRT `os.open()` does not support `O_NOFOLLOW` and Python's standard library `os.stat()` does not expose NTFS Discretionary Access Control Lists (DACLs) or `TrustedInstaller` ownership without `pywin32` / `advapi32` ctypes bindings. LINUY mitigates this on Windows by validating `SystemRoot`, restricting binary resolution to `System32` / `System32\wbem`, rejecting symlinks/reparse points via `os.lstat()` / `is_symlink()`, using `os.O_CREAT | os.O_EXCL` for report creation, and verifying `os.fstat()` inodes on file reads.
- **Low**:
  - **Offline Log Integrity & Time-Window Evasion**: `auth --input` analyzes static log exports; an attacker with root/Administrator privileges on a compromised host could alter logs prior to export or space failed login attempts outside the `--window` threshold (default 300s).
  - **OpenSSH Drop-In & Match Block Scope**: `AUD-LIN-003` parses top-level directives in `/etc/ssh/sshd_config` (supporting whitespace and `=` syntax and inline `#` comments) but does not evaluate conditional `Match` blocks or unreadable `/etc/ssh/sshd_config.d/` drop-ins.
- **Informational**:
  - **Unprivileged Visibility Boundaries**: When run as a standard user (recommended default), `/etc/sudoers`, `/var/log/auth.log`, cross-user `/proc/<pid>/fd` sockets on Linux, and live Windows Security Event Logs are restricted by the OS and reported as `ERROR` or `Unavailable`.
