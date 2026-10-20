"""Cross-platform user account enumeration, session inspection, and admin membership checks.

Implements Part F (Section 14):
- users
- users --sessions
- users --admins

Clearly separates three distinct concepts:
1. Configured user accounts (local account definitions).
2. Currently logged-in sessions (active login sessions).
3. Administrative / elevated group memberships (root/sudo/wheel on Linux; Administrators on Windows).
Never confuses account count with session count, and clearly distinguishes unavailable
information (None) from a confirmed zero count (0).
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.checks.linux import (
    enumerate_linux_admins,
    enumerate_linux_sessions,
    enumerate_linux_users,
)
from sentinel.checks.windows import (
    enumerate_windows_admins,
    enumerate_windows_sessions,
    enumerate_windows_users,
)
from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import TerminalStyle, format_kv_block, format_table


@dataclass(frozen=True)
class UserEnumerationResult:
    """Unified cross-platform result for users, sessions, and administrators."""

    platform_label: str
    os_family: str
    configured_accounts_count: int | None
    active_sessions_count: int | None
    admin_accounts_count: int | None
    account_headers: tuple[str, ...]
    account_rows: tuple[tuple[str, ...], ...]
    session_headers: tuple[str, ...]
    session_rows: tuple[tuple[str, ...], ...]
    admin_headers: tuple[str, ...]
    admin_rows: tuple[tuple[str, ...], ...]
    limitations: tuple[str, ...]


def collect_users_data(
    profile: PlatformProfile | None = None,
    prefer_psutil: bool | None = None,
) -> UserEnumerationResult:
    """Collect configured accounts, logged-in sessions, and administrative memberships."""
    pf = profile or detect_platform()
    use_psutil = pf.psutil_available if prefer_psutil is None else bool(prefer_psutil)
    all_limitations: list[str] = []

    if pf.os_family == "Linux":
        u_recs, u_lims = enumerate_linux_users()
        s_recs, s_lims = enumerate_linux_sessions(prefer_psutil=use_psutil)
        a_recs, a_lims = enumerate_linux_admins()
        all_limitations.extend(u_lims)
        for lim in s_lims + a_lims:
            if lim not in all_limitations:
                all_limitations.append(lim)

        acc_rows = (
            tuple(
                (r.username, str(r.uid), str(r.gid), r.classification, r.shell, r.disabled_status)
                for r in u_recs
            )
            if u_recs is not None
            else ()
        )
        sess_rows = (
            tuple((s.username, s.terminal, s.host, s.started, s.source) for s in s_recs)
            if s_recs is not None
            else ()
        )
        adm_rows = (
            tuple((a.username, str(a.uid) if a.uid is not None else "n/a", a.privilege_basis, a.shell) for a in a_recs)
            if a_recs is not None
            else ()
        )

        return UserEnumerationResult(
            platform_label=pf.display_label,
            os_family=pf.os_family,
            configured_accounts_count=len(u_recs) if u_recs is not None else None,
            active_sessions_count=len(s_recs) if s_recs is not None else None,
            admin_accounts_count=len(a_recs) if a_recs is not None else None,
            account_headers=("Username", "UID", "GID", "Classification", "Shell", "Password/Lock State"),
            account_rows=acc_rows,
            session_headers=("Username", "Terminal/TTY", "Remote Host", "Login Time", "Evidence Source"),
            session_rows=sess_rows,
            admin_headers=("Username", "UID", "Administrative Basis", "Shell"),
            admin_rows=adm_rows,
            limitations=tuple(all_limitations),
        )

    if pf.os_family == "Windows":
        u_recs, u_lims = enumerate_windows_users()
        s_recs, s_lims = enumerate_windows_sessions(prefer_psutil=use_psutil)
        a_recs, a_lims = enumerate_windows_admins()
        all_limitations.extend(u_lims)
        for lim in s_lims + a_lims:
            if lim not in all_limitations:
                all_limitations.append(lim)

        acc_rows = (
            tuple((r.username, r.account_type, r.enabled_status, r.evidence_source) for r in u_recs)
            if u_recs is not None
            else ()
        )
        sess_rows = (
            tuple((s.username, s.session_name, s.state, s.logon_time, s.source) for s in s_recs)
            if s_recs is not None
            else ()
        )
        adm_rows = (
            tuple((a.identity, a.member_type, a.source) for a in a_recs)
            if a_recs is not None
            else ()
        )

        return UserEnumerationResult(
            platform_label=pf.display_label,
            os_family=pf.os_family,
            configured_accounts_count=len(u_recs) if u_recs is not None else None,
            active_sessions_count=len(s_recs) if s_recs is not None else None,
            admin_accounts_count=len(a_recs) if a_recs is not None else None,
            account_headers=("Username", "Account Classification", "Enabled State", "Evidence Source"),
            account_rows=acc_rows,
            session_headers=("Username", "Session Name", "State", "Logon Time", "Evidence Source"),
            session_rows=sess_rows,
            admin_headers=("Identity", "Member Type", "Evidence Source"),
            admin_rows=adm_rows,
            limitations=tuple(all_limitations),
        )

    return UserEnumerationResult(
        platform_label=pf.display_label,
        os_family=pf.os_family,
        configured_accounts_count=None,
        active_sessions_count=None,
        admin_accounts_count=None,
        account_headers=("Username", "Details"),
        account_rows=(),
        session_headers=("Username", "Terminal"),
        session_rows=(),
        admin_headers=("Username", "Basis"),
        admin_rows=(),
        limitations=(f"User enumeration is not supported on OS family '{pf.os_family}'.",),
    )


def _format_count(count: int | None) -> str:
    if count is None:
        return "Unavailable (permission or utility limitation)"
    return str(count)


def render_users_command(
    sessions_only: bool = False,
    admins_only: bool = False,
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
    prefer_psutil: bool | None = None,
) -> tuple[str, list[Finding]]:
    """Render output and generate Finding records for 'users', 'users --sessions', or 'users --admins'."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    data = collect_users_data(pf, prefer_psutil=prefer_psutil)
    now = utc_now_iso()

    summary_kv = [
        ("Platform", data.platform_label),
        ("1. Configured User Accounts", _format_count(data.configured_accounts_count)),
        ("2. Active Logged-In Sessions", _format_count(data.active_sessions_count)),
        ("3. Administrative Accounts", _format_count(data.admin_accounts_count)),
    ]

    lines = [
        st.header("USER, SESSION, AND ADMINISTRATIVE ACCOUNT INSPECTION"),
        "Note: Configured accounts, active login sessions, and administrative memberships are separate metrics.",
        format_kv_block(summary_kv),
    ]

    show_accounts = not sessions_only and not admins_only
    show_sessions = sessions_only or (not sessions_only and not admins_only)
    show_admins = admins_only or (not sessions_only and not admins_only)

    if show_accounts:
        lines.append(st.section(f"Configured User Accounts ({_format_count(data.configured_accounts_count)})"))
        if data.configured_accounts_count is None:
            lines.append("  [ERROR/UNAVAILABLE] Could not enumerate configured accounts on this host.")
        else:
            lines.append(format_table(data.account_headers, data.account_rows, max_col_width=44))

    if show_sessions:
        lines.append(st.section(f"Currently Logged-In Sessions ({_format_count(data.active_sessions_count)})"))
        if data.active_sessions_count is None:
            lines.append("  [UNAVAILABLE] Active session information could not be retrieved.")
        elif data.active_sessions_count == 0:
            lines.append("  Confirmed 0 active interactive utmp/console login sessions.")
        else:
            lines.append(format_table(data.session_headers, data.session_rows, max_col_width=40))

    if show_admins:
        lines.append(st.section(f"Administrative / Elevated Accounts ({_format_count(data.admin_accounts_count)})"))
        if data.admin_accounts_count is None:
            lines.append("  [UNAVAILABLE] Administrative group membership could not be retrieved.")
        elif data.admin_accounts_count == 0:
            lines.append("  Confirmed 0 accounts found in inspected administrative groups.")
        else:
            lines.append(format_table(data.admin_headers, data.admin_rows, max_col_width=44))

    if data.limitations:
        lines.append(st.section("Inspection Scope & Limitations"))
        for lim in data.limitations:
            lines.append(f"  - {lim}")

    findings: list[Finding] = []
    lim_str = " | ".join(data.limitations)

    # Determine status honestly: never mark unavailable/failed checks as PASS.
    if pf.os_family not in ("Linux", "Windows"):
        status = FindingStatus.UNSUPPORTED.value
        sev = Severity.INFO.value
    elif (
        (sessions_only and data.active_sessions_count is None)
        or (admins_only and data.admin_accounts_count is None)
        or (
            data.configured_accounts_count is None
            and data.active_sessions_count is None
            and data.admin_accounts_count is None
        )
    ):
        status = FindingStatus.ERROR.value
        sev = Severity.LOW.value
    elif (
        data.configured_accounts_count is None
        or data.active_sessions_count is None
        or data.admin_accounts_count is None
        or (data.admin_accounts_count or 0) > 2
    ):
        status = FindingStatus.REVIEW.value
        sev = Severity.LOW.value
    else:
        status = FindingStatus.PASS.value
        sev = Severity.INFO.value

    admin_names = [row[0] for row in data.admin_rows]
    findings.append(
        Finding(
            finding_id="USR-0001",
            rule_id="USR-ENUM-001",
            title="User, Session, and Administrator Inventory",
            severity=sev,
            status=status,
            platform=data.platform_label,
            description=(
                f"Enumerated {_format_count(data.configured_accounts_count)} configured account(s), "
                f"{_format_count(data.active_sessions_count)} active session(s), and "
                f"{_format_count(data.admin_accounts_count)} administrative identity(ies)."
            ),
            evidence=(
                f"accounts={data.configured_accounts_count}; "
                f"sessions={data.active_sessions_count}; "
                f"admins={admin_names if data.admin_accounts_count is not None else None}"
            ),
            detection_rationale="Evaluated local account definitions, active login records, and elevated groups separately.",
            remediation="Review administrative accounts to confirm every elevated identity is authorized.",
            timestamp=now,
            limitations=lim_str,
            inspected_item="Local accounts, utmp/quser sessions, and admin groups",
            why_it_matters="Separating configured accounts from active sessions and admins prevents misinterpreting host exposure.",
            determination_method="Read-only inspection of OS account databases and session interfaces.",
        )
    )

    return "\n".join(lines), findings
