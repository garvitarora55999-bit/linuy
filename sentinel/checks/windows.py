"""Windows-specific read-only user/session/admin enumeration and host security audit checks.

All Windows inspections use native Python modules (winreg, os, psutil) or fixed,
allowlisted read-only system commands (net, quser, whoami) resolved strictly from
SystemRoot\\System32 and invoked with shell=False.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re

from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.utils.validation import run_allowlisted_command, sanitize_output_text


@dataclass(frozen=True)
class WindowsUserRecord:
    """Configured user account record on Windows."""

    username: str
    account_type: str
    enabled_status: str
    evidence_source: str


@dataclass(frozen=True)
class WindowsSessionRecord:
    """Logged-in user session on Windows."""

    username: str
    session_name: str
    state: str
    logon_time: str
    source: str


@dataclass(frozen=True)
class WindowsAdminRecord:
    """Member of the local Administrators group on Windows."""

    identity: str
    member_type: str
    source: str


def parse_net_user_list(stdout: str) -> list[str]:
    """Parse account names from 'net user' table output."""
    lines = stdout.splitlines()
    collecting = False
    usernames: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("---"):
            collecting = True
            continue
        if collecting:
            if stripped.lower().startswith("the command completed"):
                break
            tokens = [t.strip() for t in re.split(r"\s{2,}", stripped) if t.strip()]
            for tok in tokens:
                clean = sanitize_output_text(tok, 64)
                if clean and clean not in usernames:
                    usernames.append(clean)
    return usernames


def parse_net_user_detail(username: str, stdout: str) -> tuple[str, str]:
    """Parse (account_active_status, account_type_hint) from 'net user <name>' output."""
    active_status = "Unknown"
    comment = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("account active"):
            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                active_status = sanitize_output_text(parts[2], 32)
        elif lower.startswith("comment"):
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                comment = sanitize_output_text(parts[1], 120)

    builtin_names = {"administrator", "guest", "defaultaccount", "wdagutilityaccount"}
    if username.lower() in builtin_names:
        acc_type = f"Built-in Local ({comment})" if comment else "Built-in Local Account"
    else:
        acc_type = "Local User Account"
    return active_status, acc_type


def parse_net_localgroup_admins(stdout: str) -> list[WindowsAdminRecord]:
    """Parse members of 'net localgroup Administrators' output."""
    lines = stdout.splitlines()
    collecting = False
    records: list[WindowsAdminRecord] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("---"):
            collecting = True
            continue
        if collecting:
            if stripped.lower().startswith("the command completed"):
                break
            identity = sanitize_output_text(stripped, 100)
            if "\\" in identity:
                m_type = "Domain / Microsoft-Linked or Scoped Identity"
            else:
                m_type = "Local Account / Group"
            records.append(
                WindowsAdminRecord(
                    identity=identity,
                    member_type=m_type,
                    source="net localgroup Administrators",
                )
            )
    return records


def parse_quser_output(stdout: str) -> list[WindowsSessionRecord]:
    """Parse active sessions from Windows 'quser' / 'query user' output.

    Active sessions have 6 columns: USERNAME, SESSIONNAME, ID, STATE, IDLE TIME, LOGON TIME.
    Disconnected sessions omit SESSIONNAME (5 columns), so cols[1] is the numeric session ID.
    """
    records: list[WindowsSessionRecord] = []
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return records

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if idx == 0 and "username" in stripped.lower() and "sessionname" in stripped.lower():
            continue
        cleaned = stripped.lstrip(">")
        cols = [c.strip() for c in re.split(r"\s{2,}", cleaned) if c.strip()]
        if not cols:
            continue
        username = sanitize_output_text(cols[0], 64)
        if len(cols) >= 6 and not cols[1].isdigit():
            session_name = sanitize_output_text(cols[1], 40)
            state = sanitize_output_text(cols[3], 32)
            logon_time = sanitize_output_text(cols[-1], 40)
        elif len(cols) >= 4 and cols[1].isdigit():
            session_name = "disconnected"
            state = sanitize_output_text(cols[2], 32)
            logon_time = sanitize_output_text(cols[-1], 40)
        else:
            session_name = sanitize_output_text(cols[1], 40) if len(cols) > 1 else "console"
            state = sanitize_output_text(cols[2], 32) if len(cols) > 2 else "Active"
            logon_time = sanitize_output_text(cols[-1], 40) if len(cols) > 3 else ""

        records.append(
            WindowsSessionRecord(
                username=username,
                session_name=session_name,
                state=state,
                logon_time=logon_time,
                source="quser",
            )
        )
    return records


def enumerate_windows_users() -> tuple[list[WindowsUserRecord] | None, list[str]]:
    """Enumerate local Windows user accounts via allowlisted 'net user'."""
    limitations: list[str] = [
        "Enumerates local SAM accounts via 'net user'. Domain directory accounts that have never "
        "cached a local profile, built-in service SIDs (NT AUTHORITY\\*), and netplwiz UI views "
        "do not represent identical identity sets."
    ]
    res = run_allowlisted_command("net", args=["user"])
    if res.missing_binary or res.timed_out or res.permission_denied or res.returncode != 0:
        limitations.append(
            f"Could not enumerate local Windows accounts via 'net user': {res.error_message or 'command failed'}."
        )
        return None, limitations

    names = parse_net_user_list(res.stdout)
    records: list[WindowsUserRecord] = []
    for name in names[:50]:
        # Guard against flag-like account names being interpreted as switches by net.exe
        if name.startswith(("/", "-")):
            records.append(
                WindowsUserRecord(
                    username=name,
                    account_type="Local Account",
                    enabled_status="Unavailable (skipped detail query for switch-like account name)",
                    evidence_source="net user",
                )
            )
            continue
        detail_res = run_allowlisted_command("net", args=["user", name], timeout=3.0)
        if detail_res.ok:
            active_status, acc_type = parse_net_user_detail(name, detail_res.stdout)
        else:
            active_status = "Unavailable (detail query failed)"
            acc_type = "Local Account"
        records.append(
            WindowsUserRecord(
                username=name,
                account_type=acc_type,
                enabled_status=active_status,
                evidence_source="net user",
            )
        )
    return records, limitations


def enumerate_windows_sessions(
    prefer_psutil: bool = True,
) -> tuple[list[WindowsSessionRecord] | None, list[str]]:
    """Enumerate logged-in sessions on Windows via psutil.users() or allowlisted 'quser'.

    Returns (None, limitations) when session data cannot be retrieved (e.g., missing
    quser on Windows Home or permission denial), never mistaking unavailable data for 0.
    """
    limitations: list[str] = []
    if prefer_psutil:
        try:
            import psutil  # type: ignore

            if psutil is not None:
                raw_users = psutil.users()
                sessions: list[WindowsSessionRecord] = []
                for u in raw_users:
                    sessions.append(
                        WindowsSessionRecord(
                            username=sanitize_output_text(getattr(u, "name", "unknown"), 64),
                            session_name=sanitize_output_text(getattr(u, "terminal", "console") or "console", 40),
                            state="Active",
                            logon_time=sanitize_output_text(str(getattr(u, "started", "")), 40),
                            source="psutil.users()",
                        )
                    )
                limitations.append(
                    "Sessions enumerated via psutil.users(); non-interactive service sessions are excluded."
                )
                return sessions, limitations
        except ImportError:
            pass
        except Exception as exc:
            limitations.append(
                f"psutil.users() failed ({sanitize_output_text(exc, 80)}); attempting 'quser' fallback."
            )

    res = run_allowlisted_command("quser", args=[])
    if res.ok:
        sessions = parse_quser_output(res.stdout)
        limitations.append("Sessions enumerated via 'quser'.")
        return sessions, limitations

    combined_output = f"{res.stdout} {res.stderr}".lower()
    if (
        not res.missing_binary
        and not res.timed_out
        and not res.permission_denied
        and "no user exists for" in combined_output
    ):
        limitations.append("quser reported 'No User exists for *' (confirmed 0 interactive sessions).")
        return [], limitations

    limitations.append(
        "Active session enumeration unavailable: neither psutil nor 'quser' succeeded "
        f"({res.error_message or f'exit code {res.returncode}'})."
    )
    return None, limitations


def enumerate_windows_admins() -> tuple[list[WindowsAdminRecord] | None, list[str]]:
    """Enumerate members of the local Administrators group on Windows."""
    limitations: list[str] = [
        "Enumerates direct members of the local 'Administrators' group. Nested Active Directory "
        "or Entra ID (Azure AD) groups require directory queries to expand."
    ]
    res = run_allowlisted_command("net", args=["localgroup", "Administrators"])
    if not res.ok:
        limitations.append(
            f"Could not read local Administrators group: {res.error_message or 'command failed'}."
        )
        return None, limitations

    records = parse_net_localgroup_admins(res.stdout)
    return records, limitations


def inspect_windows_uac_registry(reg_values: dict[str, int] | None = None) -> Finding:
    """Inspect Windows UAC registry settings (or evaluate supplied mock values for testing)."""
    now = utc_now_iso()
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    if reg_values is None:
        try:
            import winreg  # type: ignore

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
                consent_admin, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                reg_values = {
                    "EnableLUA": int(enable_lua),
                    "ConsentPromptBehaviorAdmin": int(consent_admin),
                }
        except ImportError:
            return Finding(
                finding_id="AUD-WIN-001",
                rule_id="WIN-UAC-REG-001",
                title="Windows User Account Control (UAC) Policy",
                severity=Severity.INFO.value,
                status=FindingStatus.UNSUPPORTED.value,
                platform="Windows",
                description="winreg module is not available on this non-Windows runtime.",
                evidence=f"HKLM\\{key_path} unavailable",
                detection_rationale="Checked availability of Python winreg stdlib module.",
                remediation="Run on Windows 10/11 to inspect live UAC registry policy.",
                timestamp=now,
                limitations="Requires Windows host.",
                inspected_item=f"HKLM\\{key_path} (EnableLUA, ConsentPromptBehaviorAdmin)",
                why_it_matters="Disabling UAC allows silent privilege escalation by processes running in an admin session.",
                determination_method="Read-only winreg query.",
            )
        except OSError as exc:
            return Finding(
                finding_id="AUD-WIN-001",
                rule_id="WIN-UAC-REG-001",
                title="Windows User Account Control (UAC) Policy",
                severity=Severity.LOW.value,
                status=FindingStatus.ERROR.value,
                platform="Windows",
                description=f"Unable to read UAC registry policy: {sanitize_output_text(exc, 120)}.",
                evidence=f"HKLM\\{key_path}",
                detection_rationale="winreg.OpenKey or QueryValueEx raised OSError.",
                remediation="Verify registry read permissions on HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.",
                timestamp=now,
                limitations="Registry key inaccessible.",
                inspected_item=f"HKLM\\{key_path}",
                why_it_matters="Disabling UAC weakens elevation prompts for administrative operations.",
                determination_method="Read-only winreg query.",
            )

    enable_lua = reg_values.get("EnableLUA", 0)
    consent = reg_values.get("ConsentPromptBehaviorAdmin", 0)

    if enable_lua != 1:
        status = FindingStatus.FINDING.value
        sev = Severity.HIGH.value
        desc = "Windows UAC (EnableLUA) is disabled in registry."
    elif consent == 0:
        status = FindingStatus.REVIEW.value
        sev = Severity.MEDIUM.value
        desc = "UAC is enabled (EnableLUA=1), but ConsentPromptBehaviorAdmin=0 (elevate without prompting)."
    else:
        status = FindingStatus.PASS.value
        sev = Severity.INFO.value
        desc = f"UAC is enabled (EnableLUA=1) with prompt behavior ConsentPromptBehaviorAdmin={consent}."

    return Finding(
        finding_id="AUD-WIN-001",
        rule_id="WIN-UAC-REG-001",
        title="Windows User Account Control (UAC) Policy",
        severity=sev,
        status=status,
        platform="Windows",
        description=desc,
        evidence=f"EnableLUA={enable_lua}; ConsentPromptBehaviorAdmin={consent}",
        detection_rationale="Checked EnableLUA==1 and ConsentPromptBehaviorAdmin!=0 in HKLM Policies\\System.",
        remediation="Ensure EnableLUA is 1 and ConsentPromptBehaviorAdmin is set to prompt (2 or 5).",
        timestamp=now,
        limitations="Group Policy Objects (GPO) or pending reboot changes may affect runtime UAC behavior.",
        inspected_item=f"HKLM\\{key_path} (EnableLUA, ConsentPromptBehaviorAdmin)",
        why_it_matters="UAC prevents silent administrative elevation without user awareness.",
        determination_method="Read-only inspection of Windows Registry policy values.",
    )


def run_windows_audit_checks(platform_label: str = "Windows") -> list[Finding]:
    """Run read-only security configuration checks on Windows."""
    now = utc_now_iso()
    findings: list[Finding] = [inspect_windows_uac_registry()]

    raw_path = os.environ.get("PATH", "")
    entries = [e.strip() for e in raw_path.split(";") if e.strip()]
    suspicious_entries: list[str] = []
    for entry in entries:
        if entry in (".", "..") or (not Path(entry).is_absolute() and not entry.startswith("%")):
            suspicious_entries.append(entry)

    if suspicious_entries:
        findings.append(
            Finding(
                finding_id="AUD-WIN-002",
                rule_id="WIN-PATH-002",
                title="Windows Executable PATH Hygiene",
                severity=Severity.MEDIUM.value,
                status=FindingStatus.FINDING.value,
                platform=platform_label,
                description="Current Windows PATH contains relative directory entries.",
                evidence=f"relative_entries={suspicious_entries}",
                detection_rationale="Checked each semicolon-delimited PATH entry for relative paths.",
                remediation="Remove relative directory entries from system/user PATH environment variables.",
                timestamp=now,
                limitations="Does not evaluate NTFS ACLs on every directory in PATH.",
                inspected_item="Windows PATH environment entries",
                why_it_matters="Relative PATH entries can lead to unexpected executable or DLL search-order hijacking.",
                determination_method="Read-only inspection of os.environ['PATH'].",
            )
        )
    else:
        findings.append(
            Finding(
                finding_id="AUD-WIN-002",
                rule_id="WIN-PATH-002",
                title="Windows Executable PATH Hygiene",
                severity=Severity.INFO.value,
                status=FindingStatus.PASS.value,
                platform=platform_label,
                description=f"Inspected {len(entries)} Windows PATH entries; no relative paths detected.",
                evidence=f"entries_checked={len(entries)}",
                detection_rationale="Verified all PATH entries use absolute paths.",
                remediation="Regularly review NTFS ACLs on custom third-party directories in PATH.",
                timestamp=now,
                limitations="Does not evaluate full NTFS DACLs on each directory.",
                inspected_item="Windows PATH environment entries",
                why_it_matters="Relative PATH entries can lead to executable search-order hijacking.",
                determination_method="Read-only inspection of os.environ['PATH'].",
            )
        )

    return findings
