# LINUY

**Cross-Platform, Local, Read-Only Defensive Security Inspection CLI for Windows 10/11 and Linux**

LINUY is a defensive cybersecurity inspection command-line utility written in Python 3.10+. Once installed, typing `linuy` in any terminal on **Kali Linux**, **Ubuntu**, **Debian**, or **Windows 10/11** (PowerShell and Command Prompt) immediately launches the LINUY ASCII startup screen and interactive `linuy >` prompt—without navigating into the source directory, manually activating a virtual environment, or running `python sentinel.py`.

---

## 1. Core Design Principles

1. **Strictly Local Architecture**:
   - No hosted backend, web server, HTTP listener, or remote administration interface.
   - Zero telemetry, analytics, crash uploads, or external network connections during runtime.
   - Blocks UNC network paths (`\\server\share` and `//server/share`) on input and output paths so Windows hosts never initiate outbound SMB connections or leak NetNTLMv2 hashes.
   - All inspection occurs locally on the host; generated reports are stored in `reports/` (when running from a source checkout) or the user-local state directory (`~/.local/state/linuy/reports` on Linux; `%LOCALAPPDATA%\linuy\reports` on Windows) when installed as a global CLI command.
   - Custom report directories configured via `LINUY_REPORT_DIR` must be safe, non-symlinked absolute user paths; system directories (`/`, `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/proc`, `/sys`, `/dev`, `C:\Windows`, `C:\Program Files`), credential directories (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.azure`, `.docker`), relative traversal paths (`..`), and UNC paths are rejected.
   - *Dependency Installation Note*: Running `pipx install .` or `pip install .` contacts PyPI during initial setup if dependencies (`psutil`) are not cached locally. Once installed, LINUY makes **zero** external network connections at runtime.
2. **Strictly Read-Only Security Policy**:
   - Inspects systems without modifying them.
   - Never performs privilege escalation, UAC bypass, automatic root/Administrator relaunch, process termination, account modification, firewall changes, or automatic configuration remediation.
   - Never reads `/etc/shadow` or SAM password hashes, SSH keys, browser credentials, process command-line arguments (`/proc/<pid>/cmdline`), or process environment variables (`/proc/<pid>/environ`).
   - Resolves allowlisted OS utilities strictly from trusted system directories (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin` on Linux with root-ownership and non-world-writable verification; `SystemRoot\System32` on Windows), ignoring untrusted `PATH` entries and excluding general-purpose scripting interpreters (`powershell`, `cmd`, `bash`, `sh`). On minimal Linux distributions using BusyBox/ToyBox, root-owned symlinks in trusted directories pointing to a verified root-owned `busybox`/`toybox` binary preserve the applet path in `argv[0]`.
   - Enforces streaming output bounds (`max_output_bytes`), `stdin=DEVNULL`, and execution timeouts (`proc.kill()` on timeout) on all allowlisted subprocess invocations, and enforces bounded reads (`read_bounded_file`) on system and `/proc` files.
   - Runs with standard user privileges by default and reports permission limitations honestly (never converting an `ERROR` or `UNSUPPORTED` check into a `PASS`).

---

## 2. Project Architecture

```text
linux-sentinel/
  pyproject.toml              # Modern PEP 621 package metadata & 'linuy' console script entry point
  setup.py                    # Setuptools compatibility shim
  MANIFEST.in                 # Source distribution manifest excluding tests, venvs, reports, and caches
  sentinel.py                 # Standalone source-checkout CLI entry point
  README.md                   # User and developer documentation
  SECURITY.md                 # Vulnerability disclosure policy, threat model & audit log
  LICENSE                     # MIT License
  requirements.txt            # Minimal runtime dependency (psutil>=5.9.8,<7.0.0)
  .gitignore                  # Excludes venvs, build artifacts, caches, real logs, and reports
  sentinel/
    __init__.py               # Package metadata (LINUY, version 1.0.0, read-only mode, local scope)
    __main__.py               # Enables 'python -m sentinel' execution
    cli.py                    # Console-script entry point ('linuy' -> sentinel.cli:main)
    paths.py                  # CWD-independent report directory and bundled sample resolution
    shell.py                  # Interactive 'linuy > ' command loop with TTY readline completion
    commands.py               # Shared argument parser and command dispatcher
    platform_info.py          # OS/distro detection, psutil status, utility discovery
    findings.py               # Normalized Finding model, Severity/FindingStatus enums, FindingStore
    reporting.py              # Validated JSON and CSV exporter with formula-injection defense
    samples/                  # Packaged synthetic authentication log fixtures (.jsonl, .log, .json)
    checks/
      __init__.py
      system.py               # 'system', 'doctor', and 'audit' orchestration
      network.py              # 'network' listener vs. established connection inspection
      processes.py            # 'processes' read-only enumeration (psutil, /proc, tasklist)
      authentication.py       # 'auth' log normalization (JSONL, Windows 4624/4625, syslog/PAM) & O(N) rules
      users.py                # 'users', 'users --sessions', 'users --admins' dispatcher
      windows.py              # Windows-specific account/session/admin and UAC/PATH checks
      linux.py                # Linux-specific account/session/admin and /etc, sshd, sysctl checks
    utils/
      __init__.py
      formatting.py           # LINUY ASCII startup screen, tables, Windows VT100 & ANSI styling
      permissions.py          # Read-only privilege detection and limitation explanations
      validation.py           # Trusted binary resolution, O_NOFOLLOW file handling, CSV/Unicode sanitization
  tests/                      # Automated test suite (runs with standard-library unittest)
  samples/                    # Repository-root copy of synthetic authentication log fixtures
  reports/
    .gitkeep                  # Designated local directory for source-checkout reports
```

---

## 3. Supported Operating Systems

- **Kali Linux**, **Ubuntu**, **Debian**, and other Linux distributions supporting standard `/proc` and `/etc` interfaces (Python 3.10+).
- **Windows 10 and Windows 11** (native PowerShell, Windows Terminal, or Command Prompt `cmd.exe` with Python 3.10+; no WSL or VM required).
- Other POSIX systems support portable commands (`system`, `doctor`, `auth --input <file>`, `report`) while marking Linux/Windows-specific host checks as `UNSUPPORTED`.

---

## 4. Installation, Launch, Upgrade & Uninstall Guide

After completing one of the installation options below, you can open a **new terminal in any directory** (outside the source folder, without activating a `.venv`) and type `linuy` to launch the interactive CLI. Root or Administrator privileges are **not** required to install or launch LINUY.

### 4.1 Kali Linux & Other Debian/Ubuntu Linux Distributions

Modern Kali Linux and Debian/Ubuntu distributions enforce PEP 668 (`EXTERNALLY-MANAGED`) on the system Python. Choose either **Option A (`pipx`)** or **Option B (Dedicated User Virtual Environment + `~/.local/bin` Symlink)**:

#### Option A: Install with `pipx` (Recommended on Kali Linux)
```bash
# 1. If pipx is not already installed on your Kali/Debian system:
#    sudo apt update && sudo apt install -y pipx python3-venv

# 2. Navigate into the extracted project folder once to install:
cd /path/to/linux-sentinel
pipx install .

# 3. Ensure ~/.local/bin is on your shell PATH:
pipx ensurepath
```
*(Tip for offline Kali Linux hosts where `python3-psutil` is already installed via apt: run `pipx install --system-site-packages --pip-args="--no-build-isolation --no-deps" .`)*

#### Option B: Dedicated User Virtual Environment + `~/.local/bin` Link (No `pipx` or `sudo` Required)
```bash
# 1. Create an isolated user virtual environment in ~/.local/share/linuy-venv:
cd /path/to/linux-sentinel
python3 -m venv ~/.local/share/linuy-venv

# 2. Install LINUY into that isolated environment:
~/.local/share/linuy-venv/bin/pip install .

# 3. Link the generated 'linuy' launcher into ~/.local/bin:
mkdir -p ~/.local/bin
ln -sf ~/.local/share/linuy-venv/bin/linuy ~/.local/bin/linuy
```
**Linux `PATH` Configuration**:
If `~/.local/bin` is not yet in your `PATH` (check with `echo "$PATH"`), add it to your shell profile (`~/.zshrc` on Kali Linux or `~/.bashrc` on Ubuntu/Debian):
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```
Open a **new terminal in any directory** (e.g., `cd ~`) and launch:
```bash
linuy
```

---

### 4.2 Windows 10 / 11 — PowerShell

You do **not** need Administrator privileges, WSL, or manual `.venv\Scripts` `PATH` edits. Python packaging generates a native `linuy.exe` console launcher that runs in both PowerShell and CMD without changing PowerShell execution policies.

#### Option A: Install with `pipx` in PowerShell (Recommended)
```powershell
cd C:\path\to\linux-sentinel
py -m pip install --user pipx
py -m pipx ensurepath
py -m pipx install .
```
Close and reopen PowerShell (in any folder, such as `C:\Users\<YourUser>`) and run:
```powershell
linuy
```

#### Option B: User-Scope `pip install --user` in PowerShell (No `pipx` Required)
```powershell
cd C:\path\to\linux-sentinel
py -m pip install --user .

# Ensure your Python User Scripts folder (where linuy.exe is placed) is on your User PATH:
$UserScripts = (py -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))").Trim()
$CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentUserPath -split ";" -notcontains $UserScripts) {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentUserPath;$UserScripts", "User")
    Write-Host "Added $UserScripts to User PATH. Open a new terminal to use 'linuy'."
}
```
Open a new PowerShell window in any directory and type:
```powershell
linuy
```

---

### 4.3 Windows 10 / 11 — Command Prompt (`cmd.exe`)

#### Option A: Install with `pipx` in CMD
```cmd
cd /d C:\path\to\linux-sentinel
py -m pip install --user pipx
py -m pipx ensurepath
py -m pipx install .
```
Open a new Command Prompt window in any directory and run:
```cmd
linuy
```

#### Option B: User-Scope `pip install --user` in CMD
```cmd
cd /d C:\path\to\linux-sentinel
py -m pip install --user .

:: Add your Python User Scripts directory to your User PATH (if not already present):
powershell -NoProfile -Command "$s=(py -c \"import sysconfig; print(sysconfig.get_path('scripts','nt_user'))\").Trim(); $p=[Environment]::GetEnvironmentVariable('Path','User'); if(($p -split ';') -notcontains $s){[Environment]::SetEnvironmentVariable('Path',\"$p;$s\",'User')}"
```
Open a new Command Prompt window in any directory and type:
```cmd
linuy
```

---

### 4.4 Launching, Upgrading, and Uninstalling LINUY

#### Launch from Any Working Directory
```bash
# Launch the interactive 'linuy >' shell:
linuy

# Or run a single command directly from the terminal for scripts/automation:
linuy --help
linuy --version
linuy doctor
linuy audit
linuy network
linuy processes
linuy users
linuy auth --input samples/auth_events.jsonl
linuy report --format json
linuy report --format csv
```

#### Upgrade LINUY After Pulling or Extracting an Update
- **If installed with `pipx` (Linux / Windows PowerShell / CMD)**:
  ```bash
  cd /path/to/linux-sentinel
  pipx install --force .
  ```
  *(On Windows without `pipx` directly on PATH: `py -m pipx install --force .`)*
- **If installed in `~/.local/share/linuy-venv` (Linux Option B)**:
  ```bash
  cd /path/to/linux-sentinel
  ~/.local/share/linuy-venv/bin/pip install --upgrade .
  ```
- **If installed with `pip install --user` (Windows Option B)**:
  ```powershell
  cd C:\path\to\linux-sentinel
  py -m pip install --user --upgrade .
  ```

#### Uninstall LINUY
- **If installed with `pipx` (Linux / Windows PowerShell / CMD)**:
  ```bash
  pipx uninstall linuy
  ```
  *(On Windows: `py -m pipx uninstall linuy`)*
- **If installed in `~/.local/share/linuy-venv` (Linux Option B)**:
  ```bash
  rm -f ~/.local/bin/linuy
  rm -rf ~/.local/share/linuy-venv
  ```
- **If installed with `pip install --user` (Windows Option B)**:
  ```powershell
  py -m pip uninstall linuy
  ```

---

## 5. Interactive Terminal Experience (`linuy >`)

When you open a normal terminal in any directory and type `linuy`, LINUY displays its pure 7-bit ASCII banner, version, detected OS, execution mode, and scope, followed immediately by the interactive `linuy > ` prompt:

```text
   _     ___ _   _ _   ___   __
  | |   |_ _| \ | | | | \ \ / /
  | |    | ||  \| | | | |\ V / 
  | |___ | || |\  | |_| | | |  
  |_____|___|_| \_|\___/  |_|  

  LINUY v1.0.0 -- Cross-platform defensive security inspection CLI
  --------------------------------------------------------------
  OS / Version   : Kali GNU/Linux Rolling
  Execution mode : Read-only
  Scope          : Local
  --------------------------------------------------------------
  Type 'help' to list available commands, or 'exit' to quit.

linuy >
```

Inside the interactive shell:
- **Supported Commands**: `help`, `system`, `doctor`, `audit`, `network`, `processes`, `users`, `users --sessions`, `users --admins`, `auth --input <file>`, `report --format json`, `report --format csv`, `history`, `clear`, `exit`.
- **Restrained Terminal Styling & Fallback**: Uses monochrome/bold headings and reserves color strictly for status badges (`[FINDING]`, `[REVIEW]`, `[ERROR]`) and finding severities (`CRITICAL`, `HIGH`, `MEDIUM`). Automatically enables Windows 10/11 Virtual Terminal (VT100) mode on PowerShell/CMD and degrades cleanly to plain text when `NO_COLOR` is set, `--no-color` is passed, output is redirected/piped, or the console does not support ANSI escape codes.
- **No OS Shell Passthrough**: Arbitrary operating-system commands (`ls`, `whoami`, `bash`, `cmd`, `powershell`) are rejected with a clear message.

---

## 6. Feature Semantics & Detection Logic

### 6.1 User Accounts, Logged-In Sessions, and Administrative Membership (`users`)
LINUY explicitly separates three concepts that are frequently confused:
1. **Configured User Accounts (`users`)**: Local account definitions in `/etc/passwd` (Linux) or the local SAM database via `net user` (Windows). On Linux, accounts are classified using both login shell (`/usr/sbin/nologin`, `/bin/false`) and `UID_MIN` from `/etc/login.defs`. LINUY intentionally **never reads `/etc/shadow`** or password hashes during account enumeration; password-lock status is reported as `Unavailable (shadow not read by policy)` unless interactive login is disabled by a `nologin`/`false` shell.
2. **Currently Logged-In Sessions (`users --sessions`)**: Active interactive/remote sessions from `psutil.users()`, `who` (utmp on Linux), or `quser` (Windows).
3. **Administrative Accounts (`users --admins`)**: Identities with UID 0 or membership in `sudo`, `wheel`, `admin`, or `root` groups (Linux), or members of the local `Administrators` group (Windows).
- Unavailable data (e.g., missing `quser` on Windows Home or permission errors) is reported as `Unavailable (permission or utility limitation)`, never confused with a confirmed `0` count.

### 6.2 Network & Process Inspection (`network`, `processes`)
- **`network`**: Uses `psutil.net_connections(kind="inet")` or `/proc/net/{tcp,tcp6,udp,udp6}` (Linux) / `netstat -ano` (Windows). Clearly separates **Listening / Bound Endpoints** from **Established / Other Connections**. Unfamiliar ports are not labeled malicious without evidence; wildcard listeners (`0.0.0.0` / `::`) are flagged as `REVIEW` so operators can verify firewall rules.
- **`processes`**: Enumerates PID, process name, owner, state, RSS memory, and executable path (`psutil`, `/proc/<pid>`, or `tasklist`). Inaccessible processes and processes exiting mid-scan are handled gracefully. Command-line arguments and environment variables are intentionally omitted to prevent credential leakage.

### 6.3 Authentication-Log Normalization & Detection (`auth --input <file>`)
Supports offline analysis of:
- **JSONL (`.jsonl`)**: Normalized event records (`samples/auth_events.jsonl`).
- **Windows Security Event JSON Exports (`.json`)**: Event ID `4625` (failed logon) and Event ID `4624` (successful logon) (`samples/windows_security_events.json`).
- **Linux Syslog (`auth.log` / `secure`)**: OpenSSH (`Failed password`, `Accepted password/publickey`, `Invalid user`) and PAM (`pam_unix`, `pam_sss`, etc.) authentication failures (`samples/linux_auth.log`).

**Implemented Detection Rules**:
- **`AUTH-DET-001` (Repeated Failed Logins)**: Triggers when an `(account, source_ip)` pair accumulates `>= --threshold` (default `5`) failed login attempts within a linear-time `O(N)` sliding `--window` (default `300` seconds).
- **`AUTH-DET-002` (Successful Login Following Repeated Failures)**: Triggers when a `SUCCESS` event occurs within `--window` seconds after `>= --threshold` prior `FAILURE` events for the same `(account, source_ip)`.
- **`AUTH-PARSE-001` (Malformed Record Reporting)**: Reports the exact count of malformed, non-finite numeric (`Infinity`/`NaN`), deeply nested, or unrecognized lines skipped during parsing.
- *Important*: Detections are presented as **investigation leads**, not mathematical proof of compromise. Missing timestamps, usernames, or IPs are preserved as `None` and never fabricated.

### 6.4 Finding Model & JSON/CSV Reporting (`report --format <json|csv>`)
Every check produces normalized `Finding` records with `finding_id`, `rule_id`, `title`, `severity`, `status`, `platform`, `description`, `evidence`, `detection_rationale`, `remediation`, `timestamp`, and `limitations`.
- **Severity Levels**: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- **Result States**: `PASS`, `FINDING`, `REVIEW`, `ERROR`, `UNSUPPORTED`.
- **Report Storage**: Saved inside `reports/` (in source checkouts) or `~/.local/state/linuy/reports` / `%LOCALAPPDATA%\linuy\reports` (when installed as a global package, overridable via validated `LINUY_REPORT_DIR`) with unique UTC timestamps (`sentinel_report_YYYYMMDD_HHMMSSZ.json` or `.csv`) using atomic `O_CREAT | O_EXCL | O_NOFOLLOW` creation (`0600` permissions). CSV exports sanitize formula prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`).

---

## 7. Running Automated Tests

Run the automated test suite using Python's built-in `unittest` runner (including under `-O` optimization):

```bash
# Standard test run (works offline with zero external test runner packages)
python3 -B -m unittest discover -s tests -v

# Optimized bytecode mode (-O disables assert statements)
python3 -O -B -m unittest discover -s tests -v
```
