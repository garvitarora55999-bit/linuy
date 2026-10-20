"""Linux-specific read-only user/session/admin enumeration and host security audit checks.

All functions in this module are strictly read-only. Account enumeration never opens
or reads /etc/shadow or password hashes, and reports password-lock status as
unavailable unless determinable from non-credential shell metadata.
All system configuration reads are bounded via read_bounded_file().
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re as _re
import stat

from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.utils.validation import (
    read_bounded_file,
    run_allowlisted_command,
    sanitize_output_text,
)

NOLOGIN_SHELLS: frozenset[str] = frozenset(
    {
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "/bin/sync",
        "/sbin/halt",
        "/sbin/shutdown",
    }
)

ADMIN_GROUP_NAMES: tuple[str, ...] = ("sudo", "wheel", "admin", "root")


@dataclass(frozen=True)
class LinuxUserRecord:
    """Single configured account record from /etc/passwd."""

    username: str
    uid: int
    gid: int
    home: str
    shell: str
    classification: str
    disabled_status: str


@dataclass(frozen=True)
class LinuxSessionRecord:
    """Single active logged-in session on Linux."""

    username: str
    terminal: str
    host: str
    started: str
    source: str


@dataclass(frozen=True)
class LinuxAdminRecord:
    """Account with elevated/administrative membership on Linux."""

    username: str
    uid: int | None
    privilege_basis: str
    shell: str


def read_uid_min(login_defs_path: Path = Path("/etc/login.defs")) -> tuple[int, str]:
    """Read UID_MIN from /etc/login.defs if present, falling back to 1000 with documented note."""
    try:
        if login_defs_path.is_file() and os.access(login_defs_path, os.R_OK):
            content = read_bounded_file(login_defs_path, max_bytes=262144, allow_symlinks=False)
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
                    return int(parts[1]), f"UID_MIN={parts[1]} (from {login_defs_path})"
    except (OSError, ValueError):
        pass
    return 1000, "UID_MIN=1000 (default fallback; /etc/login.defs unavailable)"


def enumerate_linux_users(
    passwd_path: Path = Path("/etc/passwd"),
    login_defs_path: Path = Path("/etc/login.defs"),
) -> tuple[list[LinuxUserRecord] | None, list[str]]:
    """Enumerate configured local user accounts on Linux from /etc/passwd.

    Security & Privacy Policy:
    Does NOT open, read, or parse /etc/shadow or any password hash database.
    Password-lock status is reported as unavailable unless interactive login is
    explicitly disabled via a non-interactive login shell in /etc/passwd.
    """
    limitations: list[str] = []
    uid_min, uid_min_note = read_uid_min(login_defs_path)
    limitations.append(
        f"Account classification combines shell and {uid_min_note}; custom service accounts "
        "may use UIDs >= UID_MIN or interactive shells."
    )
    limitations.append(
        "Password-lock status is unavailable because LINUY does not read /etc/shadow "
        "or password hashes during account enumeration."
    )

    try:
        if not passwd_path.is_file():
            limitations.append(f"Account database {passwd_path} not found.")
            return None, limitations
        raw_text = read_bounded_file(passwd_path, max_bytes=1024 * 1024, allow_symlinks=False)
    except PermissionError:
        limitations.append(f"Permission denied reading {passwd_path}.")
        return None, limitations
    except (OSError, ValueError) as exc:
        limitations.append(f"Error reading {passwd_path}: {sanitize_output_text(exc, 120)}.")
        return None, limitations

    records: list[LinuxUserRecord] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(":")
        if len(parts) < 7:
            continue
        username = sanitize_output_text(parts[0], 64)
        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            continue
        home = sanitize_output_text(parts[5], 120)
        shell = sanitize_output_text(parts[6], 80)

        has_nologin = shell in NOLOGIN_SHELLS or shell.endswith("/nologin") or shell.endswith("/false")
        if uid == 0:
            classification = "Root / Superuser (UID 0)"
        elif has_nologin:
            classification = "System / Service (Non-interactive shell)"
        elif uid >= uid_min and uid != 65534:
            classification = f"Standard / Interactive (UID >= {uid_min})"
        else:
            classification = f"System Account with Login Shell (UID < {uid_min})"

        if has_nologin:
            disabled_status = "Shell nologin/false (password-lock unavailable; shadow not read)"
        else:
            disabled_status = "Unavailable (shadow not read by policy)"

        records.append(
            LinuxUserRecord(
                username=username,
                uid=uid,
                gid=gid,
                home=home,
                shell=shell,
                classification=classification,
                disabled_status=disabled_status,
            )
        )
    return records, limitations


def parse_who_output(stdout: str) -> list[LinuxSessionRecord]:
    """Parse output of POSIX 'who' into LinuxSessionRecord objects."""
    sessions: list[LinuxSessionRecord] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        username = sanitize_output_text(parts[0], 64)
        terminal = sanitize_output_text(parts[1], 40) if len(parts) > 1 else "tty"
        started = " ".join(parts[2:4]) if len(parts) >= 4 else (parts[2] if len(parts) == 3 else "")
        host = "local"
        if stripped.endswith(")") and "(" in stripped:
            host = stripped[stripped.rfind("(") + 1 : -1]
        sessions.append(
            LinuxSessionRecord(
                username=username,
                terminal=terminal,
                host=sanitize_output_text(host, 80),
                started=sanitize_output_text(started, 40),
                source="who (utmp)",
            )
        )
    return sessions


def enumerate_linux_sessions(
    prefer_psutil: bool = True,
) -> tuple[list[LinuxSessionRecord] | None, list[str]]:
    """Enumerate currently logged-in sessions on Linux using psutil or allowlisted 'who'.

    Returns (None, limitations) when session data cannot be retrieved due to missing
    utilities, permission errors, or execution failures—never confusing unavailable
    data with a confirmed 0 count.
    """
    limitations: list[str] = []
    if prefer_psutil:
        try:
            import psutil  # type: ignore

            if psutil is not None:
                raw_users = psutil.users()
                sessions: list[LinuxSessionRecord] = []
                for u in raw_users:
                    sessions.append(
                        LinuxSessionRecord(
                            username=sanitize_output_text(getattr(u, "name", "unknown"), 64),
                            terminal=sanitize_output_text(getattr(u, "terminal", "tty") or "tty", 40),
                            host=sanitize_output_text(getattr(u, "host", "local") or "local", 80),
                            started=sanitize_output_text(str(getattr(u, "started", "")), 40),
                            source="psutil.users()",
                        )
                    )
                limitations.append(
                    "Session list reflects utmp/active login records via psutil.users(); "
                    "non-interactive background tasks do not register utmp sessions."
                )
                return sessions, limitations
        except ImportError:
            pass
        except Exception as exc:
            limitations.append(
                f"psutil.users() error ({sanitize_output_text(exc, 80)}); falling back to 'who'."
            )

    res = run_allowlisted_command("who", args=[])
    if res.missing_binary:
        limitations.append(
            "Active session count is unavailable: neither psutil nor trusted '/usr/bin/who' is available."
        )
        return None, limitations
    if res.timed_out or res.permission_denied or res.returncode != 0:
        limitations.append(
            f"Active session count is unavailable: 'who' failed ({res.error_message or f'exit code {res.returncode}'})."
        )
        return None, limitations

    sessions = parse_who_output(res.stdout)
    limitations.append(
        "Session count is read from utmp via 'who'; container shells or processes started "
        "without a controlling login tty may show 0 utmp sessions."
    )
    return sessions, limitations


def enumerate_linux_admins(
    passwd_path: Path = Path("/etc/passwd"),
    group_path: Path = Path("/etc/group"),
) -> tuple[list[LinuxAdminRecord] | None, list[str]]:
    """Enumerate Linux accounts with UID 0 or membership in administrative groups (sudo, wheel, admin, root)."""
    limitations: list[str] = [
        "Administrative membership is determined from UID 0 and /etc/group (sudo, wheel, admin, root). "
        "Direct user rules in /etc/sudoers or Polkit/LDAP policies may grant additional privileges."
    ]
    users, user_lims = enumerate_linux_users(passwd_path=passwd_path)
    if users is None:
        return None, limitations + user_lims

    user_by_name = {u.username: u for u in users}
    user_by_gid: dict[int, list[LinuxUserRecord]] = {}
    for u in users:
        user_by_gid.setdefault(u.gid, []).append(u)

    admin_reasons: dict[str, list[str]] = {}
    for u in users:
        if u.uid == 0:
            admin_reasons.setdefault(u.username, []).append("UID 0 (Superuser)")

    try:
        if not group_path.is_file():
            limitations.append(f"Group database {group_path} not found.")
            return None, limitations
        group_text = read_bounded_file(group_path, max_bytes=1024 * 1024, allow_symlinks=False)
    except PermissionError:
        limitations.append(f"Permission denied reading {group_path}.")
        return None, limitations
    except (OSError, ValueError) as exc:
        limitations.append(f"Error reading {group_path}: {sanitize_output_text(exc, 120)}.")
        return None, limitations

    for line in group_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(":")
        if len(parts) < 4:
            continue
        gname = sanitize_output_text(parts[0], 64)
        if gname not in ADMIN_GROUP_NAMES:
            continue
        try:
            gid = int(parts[2])
        except ValueError:
            gid = -1
        members = [sanitize_output_text(m.strip(), 64) for m in parts[3].split(",") if m.strip()]
        for m in members:
            admin_reasons.setdefault(m, []).append(f"group:{gname}")
        for primary_user in user_by_gid.get(gid, []):
            tag = f"primary_gid:{gname}"
            if tag not in admin_reasons.setdefault(primary_user.username, []):
                admin_reasons[primary_user.username].append(tag)

    admins: list[LinuxAdminRecord] = []
    for uname, reasons in sorted(admin_reasons.items()):
        u_rec = user_by_name.get(uname)
        admins.append(
            LinuxAdminRecord(
                username=uname,
                uid=u_rec.uid if u_rec else None,
                privilege_basis=", ".join(reasons),
                shell=u_rec.shell if u_rec else "unknown",
            )
        )
    return admins, limitations


def run_linux_audit_checks(
    platform_label: str = "Linux",
    root_prefix: Path = Path("/"),
) -> list[Finding]:
    """Run read-only defensive configuration and permission checks on Linux."""
    findings: list[Finding] = []
    now = utc_now_iso()

    # Check 1: /etc/passwd and /etc/group permissions
    passwd_file = root_prefix / "etc" / "passwd"
    group_file = root_prefix / "etc" / "group"
    try:
        pw_stat = passwd_file.stat()
        gr_stat = group_file.stat()
        pw_mode = stat.S_IMODE(pw_stat.st_mode)
        gr_mode = stat.S_IMODE(gr_stat.st_mode)
        pw_world_write = bool(pw_mode & stat.S_IWOTH) or bool(pw_mode & stat.S_IWGRP)
        gr_world_write = bool(gr_mode & stat.S_IWOTH) or bool(gr_mode & stat.S_IWGRP)
        non_root_owner = (pw_stat.st_uid != 0) or (gr_stat.st_uid != 0)

        if pw_world_write or gr_world_write or non_root_owner:
            status = FindingStatus.FINDING.value
            sev = Severity.CRITICAL.value
            desc = "Account or group database has overly permissive write permissions or non-root ownership."
        else:
            status = FindingStatus.PASS.value
            sev = Severity.INFO.value
            desc = "/etc/passwd and /etc/group are owned by UID 0 and not group/world-writable."

        findings.append(
            Finding(
                finding_id="AUD-LIN-001",
                rule_id="LIN-FS-PASSWD-001",
                title="Account and Group Database Permissions (/etc/passwd, /etc/group)",
                severity=sev,
                status=status,
                platform=platform_label,
                description=desc,
                evidence=(
                    f"/etc/passwd mode={oct(pw_mode)} uid={pw_stat.st_uid}; "
                    f"/etc/group mode={oct(gr_mode)} uid={gr_stat.st_uid}"
                ),
                detection_rationale="Checked POSIX mode bits for group/world write flags and UID 0 ownership.",
                remediation="Verify ownership is root:root and permissions are 0644 on /etc/passwd and /etc/group.",
                timestamp=now,
                limitations="Does not inspect extended POSIX ACLs or immutable file attributes.",
                inspected_item="/etc/passwd and /etc/group filesystem metadata",
                why_it_matters="Write access to /etc/passwd or /etc/group allows arbitrary local privilege escalation.",
                determination_method="Read-only os.stat() inspection of mode bits and owner UID.",
            )
        )
    except OSError as exc:
        findings.append(
            Finding(
                finding_id="AUD-LIN-001",
                rule_id="LIN-FS-PASSWD-001",
                title="Account and Group Database Permissions (/etc/passwd, /etc/group)",
                severity=Severity.LOW.value,
                status=FindingStatus.ERROR.value,
                platform=platform_label,
                description=f"Could not stat /etc/passwd or /etc/group: {exc.strerror or 'OS error'}.",
                evidence=f"path={passwd_file}",
                detection_rationale="Attempted os.stat() on /etc/passwd and /etc/group.",
                remediation="Verify filesystem integrity and permissions on /etc.",
                timestamp=now,
                limitations="Stat call failed.",
                inspected_item="/etc/passwd and /etc/group filesystem metadata",
                why_it_matters="Write access to /etc/passwd or /etc/group allows local privilege escalation.",
                determination_method="Read-only os.stat() inspection.",
            )
        )

    # Check 2: /etc/shadow inode metadata permissions (never opens or reads /etc/shadow)
    shadow_file = root_prefix / "etc" / "shadow"
    try:
        sh_stat = shadow_file.stat()
        sh_mode = stat.S_IMODE(sh_stat.st_mode)
        world_accessible = bool(sh_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
        group_writable = bool(sh_mode & stat.S_IWGRP)
        if world_accessible or group_writable or sh_stat.st_uid != 0:
            status = FindingStatus.FINDING.value
            sev = Severity.CRITICAL.value
            desc = "/etc/shadow has unsafe permissions (world-accessible, group-writable, or non-root owner)."
        else:
            status = FindingStatus.PASS.value
            sev = Severity.INFO.value
            desc = "/etc/shadow is restricted (mode <= 0640, owned by root, no world access)."

        findings.append(
            Finding(
                finding_id="AUD-LIN-002",
                rule_id="LIN-FS-SHADOW-002",
                title="Shadow Password File Permissions (/etc/shadow)",
                severity=sev,
                status=status,
                platform=platform_label,
                description=desc,
                evidence=f"/etc/shadow mode={oct(sh_mode)} uid={sh_stat.st_uid} gid={sh_stat.st_gid}",
                detection_rationale="Verified /etc/shadow has no world permission bits, no group write bit, and UID 0.",
                remediation="If /etc/shadow is world-readable, investigate unauthorized access and restore 0640/0600 permissions.",
                timestamp=now,
                limitations="Inspects inode mode bits via os.stat() only; never opens or reads /etc/shadow.",
                inspected_item="/etc/shadow inode permissions and ownership",
                why_it_matters="Exposure of /etc/shadow allows offline password hash cracking by local users.",
                determination_method="Read-only os.stat() metadata check on /etc/shadow.",
            )
        )
    except OSError as exc:
        findings.append(
            Finding(
                finding_id="AUD-LIN-002",
                rule_id="LIN-FS-SHADOW-002",
                title="Shadow Password File Permissions (/etc/shadow)",
                severity=Severity.LOW.value,
                status=FindingStatus.ERROR.value,
                platform=platform_label,
                description=f"Unable to inspect /etc/shadow metadata: {exc.strerror or 'OS error'}.",
                evidence=f"path={shadow_file}",
                detection_rationale="Attempted os.stat() on /etc/shadow.",
                remediation="Verify whether /etc/shadow exists on this distribution.",
                timestamp=now,
                limitations="Inode metadata unavailable.",
                inspected_item="/etc/shadow inode permissions and ownership",
                why_it_matters="Exposure of /etc/shadow allows offline password hash cracking.",
                determination_method="Read-only os.stat() check on /etc/shadow.",
            )
        )

    # Check 3: SSH daemon configuration (/etc/ssh/sshd_config)
    sshd_config = root_prefix / "etc" / "ssh" / "sshd_config"
    if not sshd_config.exists():
        findings.append(
            Finding(
                finding_id="AUD-LIN-003",
                rule_id="LIN-SSH-CONFIG-003",
                title="OpenSSH Server Configuration (/etc/ssh/sshd_config)",
                severity=Severity.INFO.value,
                status=FindingStatus.UNSUPPORTED.value,
                platform=platform_label,
                description="/etc/ssh/sshd_config is not present (OpenSSH server does not appear installed).",
                evidence=f"path={sshd_config} (not found)",
                detection_rationale="Checked for presence of /etc/ssh/sshd_config.",
                remediation="No action required if SSH server is intentionally not installed.",
                timestamp=now,
                limitations="Does not inspect custom sshd paths outside /etc/ssh/sshd_config.",
                inspected_item="/etc/ssh/sshd_config directives (PermitRootLogin, PermitEmptyPasswords)",
                why_it_matters="Misconfigured SSH servers can allow root password brute-forcing or empty-password logins.",
                determination_method="Read-only parsing of active directives in /etc/ssh/sshd_config.",
            )
        )
    elif not os.access(sshd_config, os.R_OK):
        findings.append(
            Finding(
                finding_id="AUD-LIN-003",
                rule_id="LIN-SSH-CONFIG-003",
                title="OpenSSH Server Configuration (/etc/ssh/sshd_config)",
                severity=Severity.LOW.value,
                status=FindingStatus.ERROR.value,
                platform=platform_label,
                description="Permission denied reading /etc/ssh/sshd_config with current user privileges.",
                evidence=f"path={sshd_config} readable=False",
                detection_rationale="os.access('/etc/ssh/sshd_config', os.R_OK) returned False.",
                remediation="Inspect /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/ with appropriate read access.",
                timestamp=now,
                limitations="Cannot read restricted sshd_config as unprivileged user.",
                inspected_item="/etc/ssh/sshd_config directives",
                why_it_matters="Misconfigured SSH servers can allow root password brute-forcing or empty-password logins.",
                determination_method="Read-only parsing of /etc/ssh/sshd_config.",
            )
        )
    else:
        try:
            directives: dict[str, str] = {}
            sshd_text = read_bounded_file(sshd_config, max_bytes=262144, allow_symlinks=False)
            for line in sshd_text.splitlines():
                uncommented = line.split("#", 1)[0].strip()
                if not uncommented:
                    continue
                parts = _re.split(r"[\s=]+", uncommented, maxsplit=1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    val = parts[1].strip().strip('"').strip("'")
                    if key and key not in directives:
                        directives[key] = sanitize_output_text(val, 60).lower()

            permit_root = directives.get("permitrootlogin", "default (prohibit-password)")
            permit_empty = directives.get("permitemptypasswords", "default (no)")
            password_auth = directives.get("passwordauthentication", "default (yes)")

            if permit_empty == "yes" or permit_root == "yes":
                status = FindingStatus.FINDING.value
                sev = Severity.HIGH.value
                desc = "SSH configuration explicitly allows root password login or empty passwords."
            elif password_auth == "yes":
                status = FindingStatus.REVIEW.value
                sev = Severity.LOW.value
                desc = "SSH configuration allows password authentication; review whether key-only auth is appropriate."
            else:
                status = FindingStatus.PASS.value
                sev = Severity.INFO.value
                desc = "SSH configuration does not explicitly enable PermitRootLogin=yes or PermitEmptyPasswords=yes."

            findings.append(
                Finding(
                    finding_id="AUD-LIN-003",
                    rule_id="LIN-SSH-CONFIG-003",
                    title="OpenSSH Server Configuration (/etc/ssh/sshd_config)",
                    severity=sev,
                    status=status,
                    platform=platform_label,
                    description=desc,
                    evidence=(
                        f"PermitRootLogin={permit_root}; PermitEmptyPasswords={permit_empty}; "
                        f"PasswordAuthentication={password_auth}"
                    ),
                    detection_rationale="Parsed top-level directives from /etc/ssh/sshd_config.",
                    remediation="Review /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/ drop-ins (`sshd -T` as root).",
                    timestamp=now,
                    limitations="Include files in /etc/ssh/sshd_config.d/ or Match blocks may override base directives.",
                    inspected_item="/etc/ssh/sshd_config (PermitRootLogin, PermitEmptyPasswords, PasswordAuthentication)",
                    why_it_matters="Weak SSH authentication settings increase exposure to remote credential attacks.",
                    determination_method="Read-only parsing of non-comment lines in /etc/ssh/sshd_config.",
                )
            )
        except (OSError, ValueError) as exc:
            findings.append(
                Finding(
                    finding_id="AUD-LIN-003",
                    rule_id="LIN-SSH-CONFIG-003",
                    title="OpenSSH Server Configuration (/etc/ssh/sshd_config)",
                    severity=Severity.LOW.value,
                    status=FindingStatus.ERROR.value,
                    platform=platform_label,
                    description=f"Error reading /etc/ssh/sshd_config: {sanitize_output_text(exc, 120)}.",
                    evidence=f"path={sshd_config}",
                    detection_rationale="File read failed.",
                    remediation="Check permissions on /etc/ssh/sshd_config.",
                    timestamp=now,
                    limitations="Unable to parse file.",
                    inspected_item="/etc/ssh/sshd_config",
                    why_it_matters="Weak SSH settings increase remote attack surface.",
                    determination_method="Read-only file read.",
                )
            )

    # Check 4: Kernel sysctl hardening parameters (/proc/sys)
    sysctl_targets = {
        "kernel.randomize_va_space": (root_prefix / "proc" / "sys" / "kernel" / "randomize_va_space", "2"),
        "fs.protected_symlinks": (root_prefix / "proc" / "sys" / "fs" / "protected_symlinks", "1"),
        "fs.protected_hardlinks": (root_prefix / "proc" / "sys" / "fs" / "protected_hardlinks", "1"),
    }
    observed_sysctls: dict[str, str] = {}
    weak_sysctls: list[str] = []
    for name, (sys_path, expected) in sysctl_targets.items():
        try:
            if sys_path.is_file() and os.access(sys_path, os.R_OK):
                val = read_bounded_file(sys_path, max_bytes=4096, allow_symlinks=False).strip()
                observed_sysctls[name] = val
                if val != expected:
                    weak_sysctls.append(f"{name}={val} (recommended {expected})")
        except (OSError, ValueError):
            continue

    if not observed_sysctls:
        findings.append(
            Finding(
                finding_id="AUD-LIN-004",
                rule_id="LIN-SYSCTL-004",
                title="Kernel Memory and Link Hardening (/proc/sys)",
                severity=Severity.INFO.value,
                status=FindingStatus.UNSUPPORTED.value,
                platform=platform_label,
                description="Kernel /proc/sys hardening parameters are not accessible in this environment.",
                evidence="No readable files under /proc/sys/kernel or /proc/sys/fs.",
                detection_rationale="Checked readability of /proc/sys kernel parameters.",
                remediation="Verify whether running inside a restricted container without /proc/sys exposure.",
                timestamp=now,
                limitations="Containerized environments may mask or restrict /proc/sys nodes.",
                inspected_item="kernel.randomize_va_space, fs.protected_symlinks, fs.protected_hardlinks",
                why_it_matters="ASLR and symlink/hardlink protections mitigate memory corruption and /tmp race attacks.",
                determination_method="Read-only inspection of /proc/sys virtual files.",
            )
        )
    elif weak_sysctls:
        findings.append(
            Finding(
                finding_id="AUD-LIN-004",
                rule_id="LIN-SYSCTL-004",
                title="Kernel Memory and Link Hardening (/proc/sys)",
                severity=Severity.MEDIUM.value,
                status=FindingStatus.FINDING.value,
                platform=platform_label,
                description=f"One or more kernel hardening parameters differ from defensive defaults: {', '.join(weak_sysctls)}.",
                evidence="; ".join(f"{k}={v}" for k, v in observed_sysctls.items()),
                detection_rationale="Compared active /proc/sys values against standard hardening settings.",
                remediation="Investigate /etc/sysctl.conf and /etc/sysctl.d/ to verify if settings were weakened.",
                timestamp=now,
                limitations="In containers, /proc/sys values may reflect host kernel or namespace defaults.",
                inspected_item="kernel.randomize_va_space, fs.protected_symlinks, fs.protected_hardlinks",
                why_it_matters="ASLR and symlink/hardlink protections mitigate memory corruption and /tmp race attacks.",
                determination_method="Read-only inspection of /proc/sys virtual files.",
            )
        )
    else:
        findings.append(
            Finding(
                finding_id="AUD-LIN-004",
                rule_id="LIN-SYSCTL-004",
                title="Kernel Memory and Link Hardening (/proc/sys)",
                severity=Severity.INFO.value,
                status=FindingStatus.PASS.value,
                platform=platform_label,
                description="ASLR (randomize_va_space=2) and symlink/hardlink protections are enabled.",
                evidence="; ".join(f"{k}={v}" for k, v in observed_sysctls.items()),
                detection_rationale="All readable /proc/sys hardening values matched defensive expectations.",
                remediation="No action required.",
                timestamp=now,
                limitations="Reflects current runtime state; check /etc/sysctl.d/ for persistence across reboots.",
                inspected_item="kernel.randomize_va_space, fs.protected_symlinks, fs.protected_hardlinks",
                why_it_matters="ASLR and symlink/hardlink protections mitigate memory corruption and /tmp race attacks.",
                determination_method="Read-only inspection of /proc/sys virtual files.",
            )
        )

    # Check 5: Sudoers Policy & Permissions (/etc/sudoers)
    sudoers_file = root_prefix / "etc" / "sudoers"
    if not sudoers_file.exists():
        findings.append(
            Finding(
                finding_id="AUD-LIN-005",
                rule_id="LIN-SUDOERS-005",
                title="Sudoers Configuration and NOPASSWD Rules (/etc/sudoers)",
                severity=Severity.INFO.value,
                status=FindingStatus.UNSUPPORTED.value,
                platform=platform_label,
                description="/etc/sudoers is not present on this system (sudo may not be installed).",
                evidence=f"path={sudoers_file} (missing)",
                detection_rationale="Checked existence of /etc/sudoers.",
                remediation="No action needed if sudo is not used.",
                timestamp=now,
                limitations="Does not inspect Polkit or doas configurations.",
                inspected_item="/etc/sudoers permissions and NOPASSWD directives",
                why_it_matters="NOPASSWD sudo rules or writable sudoers files allow immediate root escalation.",
                determination_method="Read-only stat and text scan of /etc/sudoers.",
            )
        )
    elif not os.access(sudoers_file, os.R_OK):
        try:
            su_stat = sudoers_file.stat()
            mode_str = oct(stat.S_IMODE(su_stat.st_mode))
        except OSError:
            mode_str = "unknown"
        findings.append(
            Finding(
                finding_id="AUD-LIN-005",
                rule_id="LIN-SUDOERS-005",
                title="Sudoers Configuration and NOPASSWD Rules (/etc/sudoers)",
                severity=Severity.INFO.value,
                status=FindingStatus.ERROR.value,
                platform=platform_label,
                description=(
                    f"Cannot read {sudoers_file} contents with current unprivileged user permissions "
                    f"(file mode={mode_str})."
                ),
                evidence=f"path={sudoers_file}; mode={mode_str}; readable=False",
                detection_rationale="os.access('/etc/sudoers', os.R_OK) is False for non-root users by design (mode 0440).",
                remediation="To audit NOPASSWD rules inside /etc/sudoers and /etc/sudoers.d/, review with root read access.",
                timestamp=now,
                limitations="Standard users cannot read /etc/sudoers contents when permissions are properly set to 0440.",
                inspected_item="/etc/sudoers and /etc/sudoers.d/ directives",
                why_it_matters="Broad NOPASSWD rules allow compromised user sessions to escalate to root without authentication.",
                determination_method="Checked os.stat() and os.access(R_OK) on /etc/sudoers.",
            )
        )
    else:
        nopasswd_lines: list[str] = []
        try:
            sudoers_text = read_bounded_file(sudoers_file, max_bytes=262144, allow_symlinks=False)
            for line in sudoers_text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "NOPASSWD" in stripped:
                    nopasswd_lines.append(sanitize_output_text(stripped, 100))
        except (OSError, ValueError):
            pass
        sudoers_d = root_prefix / "etc" / "sudoers.d"
        if sudoers_d.is_dir() and os.access(sudoers_d, os.R_OK | os.X_OK):
            for child in sorted(sudoers_d.iterdir()):
                if child.is_file() and not child.is_symlink() and os.access(child, os.R_OK):
                    try:
                        child_text = read_bounded_file(child, max_bytes=262144, allow_symlinks=False)
                        for line in child_text.splitlines():
                            stripped = line.strip()
                            if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                                nopasswd_lines.append(f"{child.name}: {sanitize_output_text(stripped, 80)}")
                    except (OSError, ValueError):
                        continue

        if nopasswd_lines:
            findings.append(
                Finding(
                    finding_id="AUD-LIN-005",
                    rule_id="LIN-SUDOERS-005",
                    title="Sudoers Configuration and NOPASSWD Rules (/etc/sudoers)",
                    severity=Severity.MEDIUM.value,
                    status=FindingStatus.REVIEW.value,
                    platform=platform_label,
                    description=f"Found {len(nopasswd_lines)} sudoers rule(s) granting NOPASSWD execution.",
                    evidence="; ".join(nopasswd_lines[:3]),
                    detection_rationale="Scanned /etc/sudoers and /etc/sudoers.d/ for active NOPASSWD directives.",
                    remediation="Verify each NOPASSWD entry is intentional and restricted to specific non-shell binaries.",
                    timestamp=now,
                    limitations="Does not evaluate complex sudoers alias expansion.",
                    inspected_item="/etc/sudoers and /etc/sudoers.d/ active lines",
                    why_it_matters="NOPASSWD rules allow privilege escalation without re-authenticating.",
                    determination_method="Read-only text scan of /etc/sudoers and /etc/sudoers.d/.",
                )
            )
        else:
            findings.append(
                Finding(
                    finding_id="AUD-LIN-005",
                    rule_id="LIN-SUDOERS-005",
                    title="Sudoers Configuration and NOPASSWD Rules (/etc/sudoers)",
                    severity=Severity.INFO.value,
                    status=FindingStatus.PASS.value,
                    platform=platform_label,
                    description="No active NOPASSWD directives detected in readable sudoers configuration.",
                    evidence=f"Scanned {sudoers_file}",
                    detection_rationale="Scanned active lines in /etc/sudoers and readable /etc/sudoers.d/ files.",
                    remediation="No action required.",
                    timestamp=now,
                    limitations="Unreadable drop-in files in /etc/sudoers.d/ could not be inspected if restricted.",
                    inspected_item="/etc/sudoers and /etc/sudoers.d/ active lines",
                    why_it_matters="NOPASSWD rules allow privilege escalation without re-authenticating.",
                    determination_method="Read-only text scan of /etc/sudoers and /etc/sudoers.d/.",
                )
            )

    # Check 6: World-writable directories in execution PATH
    raw_path = os.environ.get("PATH", "")
    path_dirs = [p.strip() for p in raw_path.split(os.pathsep) if p.strip()]
    writable_dirs: list[str] = []
    relative_dirs: list[str] = []
    for d_str in path_dirs:
        if d_str in (".", "") or not os.path.isabs(d_str):
            relative_dirs.append(d_str or ".")
            continue
        p_obj = Path(d_str)
        try:
            if p_obj.is_dir():
                st_info = p_obj.stat()
                mode = stat.S_IMODE(st_info.st_mode)
                if (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                    writable_dirs.append(f"{d_str} ({oct(mode)})")
        except OSError:
            continue

    if writable_dirs or relative_dirs:
        findings.append(
            Finding(
                finding_id="AUD-LIN-006",
                rule_id="LIN-PATH-PERM-006",
                title="Executable PATH Directory Permissions",
                severity=Severity.HIGH.value,
                status=FindingStatus.FINDING.value,
                platform=platform_label,
                description="Current PATH contains world-writable or relative directories susceptible to binary hijacking.",
                evidence=f"world_writable={writable_dirs}; relative={relative_dirs}",
                detection_rationale="Inspected each directory in PATH for world-write bit (0002) without sticky bit or relative paths.",
                remediation="Remove relative entries ('.') and restrict write permissions (chmod o-w) on PATH directories.",
                timestamp=now,
                limitations="Inspects the current user's PATH environment variable only.",
                inspected_item="Directories listed in current PATH",
                why_it_matters="World-writable or relative PATH directories allow local attackers to plant trojan binaries.",
                determination_method="Read-only os.stat() check on each directory in os.environ['PATH'].",
            )
        )
    else:
        findings.append(
            Finding(
                finding_id="AUD-LIN-006",
                rule_id="LIN-PATH-PERM-006",
                title="Executable PATH Directory Permissions",
                severity=Severity.INFO.value,
                status=FindingStatus.PASS.value,
                platform=platform_label,
                description=f"All {len(path_dirs)} absolute directories in PATH are protected against unprivileged world writes.",
                evidence=f"checked_dirs={len(path_dirs)}; world_writable=0; relative=0",
                detection_rationale="Verified all PATH entries are absolute and lack unsticky world-write permissions.",
                remediation="No action required.",
                timestamp=now,
                limitations="Inspects the current user's PATH environment variable only.",
                inspected_item="Directories listed in current PATH",
                why_it_matters="World-writable or relative PATH directories allow local attackers to plant trojan binaries.",
                determination_method="Read-only os.stat() check on each directory in os.environ['PATH'].",
            )
        )

    return findings
