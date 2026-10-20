"""System information ('system'), application health check ('doctor'), and audit dispatcher ('audit').

Implements Part E (Sections 9 and 10) and coordinates Part F (Section 11).
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from sentinel import (
    PACKAGE_DIR,
    __app_name__,
    __mode__,
    __scope__,
    __version__,
    get_bundled_samples_dir,
    get_source_checkout_root,
    is_safe_report_directory_path,
    resolve_default_report_dir,
)
from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import TerminalStyle, format_kv_block, format_table
from sentinel.utils.permissions import can_read_path


@dataclass(frozen=True)
class DoctorCheckItem:
    """Single health check item evaluated by 'doctor'."""

    check_id: str
    component: str
    status: str  # PASS, WARNING, ERROR, UNSUPPORTED
    details: str
    next_step: str


def collect_system_info(profile: PlatformProfile | None = None) -> dict[str, Any]:
    """Gather safe, non-sensitive system and execution metadata for the 'system' command."""
    pf = profile or detect_platform()
    priv = pf.privilege_summary
    return {
        "application": f"{__app_name__} v{__version__}",
        "execution_mode": f"{__mode__} (Scope: {__scope__})",
        "operating_system": pf.distro_name,
        "os_family": pf.os_family,
        "kernel_or_release": pf.os_release,
        "architecture": pf.architecture,
        "hostname": pf.hostname,
        "python_version": pf.python_version,
        "current_user": priv.get("username", "unknown"),
        "privilege_level": priv.get("privilege_level", "Standard User"),
        "psutil_backend": (
            f"Available (v{pf.psutil_version})"
            if pf.psutil_available
            else "Not installed (using native stdlib/OS read-only fallback)"
        ),
        "available_utilities": ", ".join(pf.available_utilities) if pf.available_utilities else "none",
        "missing_utilities": ", ".join(pf.missing_utilities) if pf.missing_utilities else "none",
        "supported_features": list(pf.supported_features),
        "unsupported_features": list(pf.unsupported_features),
        "permission_limitations": priv.get("limitation_summary", ""),
    }


def render_system_info(
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
) -> tuple[str, list[Finding]]:
    """Format 'system' output and return an informational finding record."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    info = collect_system_info(pf)

    kv_rows = [
        ("Application", info["application"]),
        ("Execution Mode", info["execution_mode"]),
        ("Operating System", info["operating_system"]),
        ("OS Family / Kernel", f"{info['os_family']} ({info['kernel_or_release']}) [{info['architecture']}]"),
        ("Hostname", info["hostname"]),
        ("Python Version", info["python_version"]),
        ("Current User", f"{info['current_user']} ({info['privilege_level']})"),
        ("psutil Dependency", info["psutil_backend"]),
        ("Available Utilities", info["available_utilities"]),
        ("Missing Utilities", info["missing_utilities"]),
    ]

    lines = [
        st.header("SYSTEM INFORMATION"),
        format_kv_block(kv_rows),
        st.section("Supported Inspection Features"),
    ]
    for feat in info["supported_features"]:
        lines.append(f"  - {feat}")

    if info["unsupported_features"]:
        lines.append(st.section("Platform-Excluded Features"))
        for ufeat in info["unsupported_features"]:
            lines.append(f"  - {ufeat}")

    lines.append(st.section("Permission Limitations"))
    lines.append(f"  {info['permission_limitations']}")

    finding = Finding(
        finding_id="SYS-0001",
        rule_id="SYS-INFO-001",
        title="System Environment Inventory",
        severity=Severity.INFO.value,
        status=FindingStatus.PASS.value,
        platform=pf.display_label,
        description=f"Collected read-only host metadata on {pf.display_label} ({pf.architecture}).",
        evidence=(
            f"OS={pf.distro_name}; Python={pf.python_version}; "
            f"User={info['current_user']}; Elevated={pf.privilege_summary.get('is_elevated')}"
        ),
        detection_rationale="Read-only inspection of Python platform APIs and trusted system utility presence.",
        remediation="Review permission limitations if deeper root/Administrator checks are required.",
        timestamp=utc_now_iso(),
        limitations=info["permission_limitations"],
        inspected_item="OS release, Python runtime, user privilege state, and trusted system utilities",
        why_it_matters="Establishes which host checks are supported and what privilege boundaries apply.",
        determination_method="Evaluated platform.uname(), /etc/os-release or win32_ver(), and trusted binary allowlist.",
    )
    return "\n".join(lines), [finding]


def run_doctor_checks(
    project_root: Path | None = None,
    profile: PlatformProfile | None = None,
    report_dir_override: Path | None = None,
) -> tuple[list[DoctorCheckItem], list[Finding]]:
    """Execute application health checks ('doctor') without modifying system settings."""
    pf = profile or detect_platform()
    items: list[DoctorCheckItem] = []

    # 1. Python version check (>= 3.10)
    if pf.python_Supported:
        items.append(
            DoctorCheckItem(
                check_id="DOC-001",
                component="Python Version",
                status="PASS",
                details=f"Python {pf.python_version} meets requirement (>= 3.10).",
                next_step="None required.",
            )
        )
    else:
        items.append(
            DoctorCheckItem(
                check_id="DOC-001",
                component="Python Version",
                status="ERROR",
                details=f"Python {pf.python_version} is older than required Python 3.10+.",
                next_step="Run LINUY using Python 3.10 or newer.",
            )
        )

    # 2. Operating System Support
    if pf.os_family in ("Linux", "Windows"):
        items.append(
            DoctorCheckItem(
                check_id="DOC-002",
                component="Operating System Support",
                status="PASS",
                details=f"Supported OS family detected: {pf.display_label}.",
                next_step="None required.",
            )
        )
    else:
        items.append(
            DoctorCheckItem(
                check_id="DOC-002",
                component="Operating System Support",
                status="UNSUPPORTED",
                details=f"OS '{pf.display_label}' is not a primary target (Windows 10/11 or Linux).",
                next_step="Host-specific checks will be skipped; imported log analysis remains available.",
            )
        )

    # 3. Dependencies (psutil)
    if pf.psutil_available:
        items.append(
            DoctorCheckItem(
                check_id="DOC-003",
                component="Dependency: psutil",
                status="PASS",
                details=f"psutil v{pf.psutil_version} is installed for cross-platform process/network inspection.",
                next_step="None required.",
            )
        )
    else:
        items.append(
            DoctorCheckItem(
                check_id="DOC-003",
                component="Dependency: psutil",
                status="WARNING",
                details="psutil is not installed; falling back to native /proc or trusted OS utilities.",
                next_step="Install psutil via 'pip install -r requirements.txt' for richer cross-platform metrics.",
            )
        )

    # 4. Application structure & samples (works for both explicit project_root and installed packages)
    if project_root is not None:
        root = Path(project_root)
        expected_modules = [
            root / "sentinel" / "__init__.py",
            root / "sentinel" / "shell.py",
            root / "sentinel" / "commands.py",
            root / "sentinel" / "findings.py",
            root / "sentinel" / "reporting.py",
        ]
        sample_dir = root / "samples" if (root / "samples").is_dir() else (root / "sentinel" / "samples")
        report_dir = report_dir_override or (root / "reports")
    else:
        checkout_root = get_source_checkout_root()
        pkg_dir = PACKAGE_DIR
        expected_modules = [
            pkg_dir / "__init__.py",
            pkg_dir / "shell.py",
            pkg_dir / "commands.py",
            pkg_dir / "findings.py",
            pkg_dir / "reporting.py",
        ]
        sample_dir = get_bundled_samples_dir()
        if report_dir_override is not None:
            report_dir = report_dir_override
        elif checkout_root is not None:
            report_dir = checkout_root / "reports"
        else:
            report_dir = resolve_default_report_dir()
        try:
            if (
                not report_dir.exists()
                and not report_dir.is_symlink()
                and is_safe_report_directory_path(report_dir)
            ):
                report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            pass

    missing_mods = [m.name for m in expected_modules if not m.is_file()]
    if not missing_mods and sample_dir.is_dir():
        items.append(
            DoctorCheckItem(
                check_id="DOC-004",
                component="Application Installation",
                status="PASS",
                details="Core application modules and sample fixtures directory are present.",
                next_step="None required.",
            )
        )
    else:
        items.append(
            DoctorCheckItem(
                check_id="DOC-004",
                component="Application Installation",
                status="ERROR",
                details=f"Missing expected project components: {missing_mods or ['samples/']}",
                next_step="Verify repository or package installation integrity.",
            )
        )

    # 5. Report directory accessibility
    if report_dir.is_symlink() or os.path.islink(report_dir):
        items.append(
            DoctorCheckItem(
                check_id="DOC-005",
                component="Report Directory Safety",
                status="ERROR",
                details=f"Report directory '{report_dir}' is a symbolic link, which is rejected for safety.",
                next_step="Replace symlink with a real local directory.",
            )
        )
    elif report_dir.is_dir() and os.access(report_dir, os.W_OK | os.X_OK):
        items.append(
            DoctorCheckItem(
                check_id="DOC-005",
                component="Report Directory Access",
                status="PASS",
                details=f"Designated report directory '{report_dir.name}/' exists and is writable.",
                next_step="None required.",
            )
        )
    else:
        items.append(
            DoctorCheckItem(
                check_id="DOC-005",
                component="Report Directory Access",
                status="ERROR",
                details=f"Report directory '{report_dir}' is missing or not writable by current user.",
                next_step="Ensure the designated report directory exists and is writable.",
            )
        )

    # 6. Available OS Inspection Utilities
    if pf.available_utilities:
        util_status = "PASS" if not pf.missing_utilities else "WARNING"
        detail_msg = f"Available in trusted system dirs: {', '.join(pf.available_utilities)}"
        if pf.missing_utilities:
            detail_msg += f" | Missing optional: {', '.join(pf.missing_utilities)}"
        items.append(
            DoctorCheckItem(
                check_id="DOC-006",
                component="System Inspection Utilities",
                status=util_status,
                details=detail_msg,
                next_step=(
                    "None required."
                    if util_status == "PASS"
                    else "Some optional fallback utilities are absent; native Python APIs will be used."
                ),
            )
        )
    else:
        items.append(
            DoctorCheckItem(
                check_id="DOC-006",
                component="System Inspection Utilities",
                status="WARNING",
                details="No external allowlisted OS utilities found in trusted system directories.",
                next_step="Relying strictly on Python stdlib and /proc or psutil APIs.",
            )
        )

    # 7. Permissions & Privilege Boundaries
    elevated = bool(pf.privilege_summary.get("is_elevated", False))
    if elevated:
        items.append(
            DoctorCheckItem(
                check_id="DOC-007",
                component="Inspection Privileges",
                status="PASS",
                details="Running with elevated privileges in read-only mode; restricted logs/configs readable.",
                next_step="Continue operating in read-only mode.",
            )
        )
    else:
        if pf.os_family == "Linux":
            sudoers_ok, _ = can_read_path("/etc/sudoers")
            auth_ok, _ = can_read_path("/var/log/auth.log")
            restricted_list = []
            if not sudoers_ok:
                restricted_list.append("/etc/sudoers (NOPASSWD rules)")
            if not auth_ok:
                restricted_list.append("/var/log/auth.log (live system auth log)")
            restricted_list.append("cross-user socket/process ownership in /proc")
            items.append(
                DoctorCheckItem(
                    check_id="DOC-007",
                    component="Inspection Privileges",
                    status="WARNING",
                    details=(
                        f"Running as unprivileged user '{pf.privilege_summary.get('username')}'. "
                        f"Restricted checks: {', '.join(restricted_list)}."
                    ),
                    next_step=(
                        "Normal user mode is recommended by default. Checks requiring root read access "
                        "will report permission limitations honestly."
                    ),
                )
            )
        elif pf.os_family == "Windows":
            items.append(
                DoctorCheckItem(
                    check_id="DOC-007",
                    component="Inspection Privileges",
                    status="WARNING",
                    details=(
                        f"Running as standard Windows user '{pf.privilege_summary.get('username')}'. "
                        "Live Security Event Log (4624/4625) and elevated process details are restricted."
                    ),
                    next_step=(
                        "Normal user mode is recommended by default. Supply exported logs via 'auth --input' "
                        "or run in an elevated read-only shell if live Security log access is needed."
                    ),
                )
            )
        else:
            items.append(
                DoctorCheckItem(
                    check_id="DOC-007",
                    component="Inspection Privileges",
                    status="WARNING",
                    details="Running without elevated privileges on an unsupported OS family.",
                    next_step="Use 'auth --input <file>' for portable log analysis.",
                )
            )

    findings: list[Finding] = []
    status_map = {
        "PASS": (FindingStatus.PASS.value, Severity.INFO.value),
        "WARNING": (FindingStatus.REVIEW.value, Severity.LOW.value),
        "ERROR": (FindingStatus.ERROR.value, Severity.MEDIUM.value),
        "UNSUPPORTED": (FindingStatus.UNSUPPORTED.value, Severity.INFO.value),
    }
    now = utc_now_iso()
    for item in items:
        f_status, f_sev = status_map.get(item.status, (FindingStatus.REVIEW.value, Severity.LOW.value))
        findings.append(
            Finding(
                finding_id=item.check_id,
                rule_id=f"DOCTOR-{item.check_id}",
                title=f"Health Check: {item.component}",
                severity=f_sev,
                status=f_status,
                platform=pf.display_label,
                description=item.details,
                evidence=f"status={item.status}; component={item.component}",
                detection_rationale="Evaluated local application runtime environment, dependencies, and permissions.",
                remediation=item.next_step,
                timestamp=now,
                limitations="Doctor checks verify application health and read-only capability, NOT host security.",
                inspected_item=item.component,
                why_it_matters="Ensures LINUY dependencies, directories, and permissions are accurately understood.",
                determination_method="Direct inspection of Python runtime, filesystem permissions, and trusted binary allowlist.",
            )
        )

    return items, findings


def render_doctor(
    project_root: Path | None = None,
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
    report_dir_override: Path | None = None,
) -> tuple[str, list[Finding]]:
    """Render the 'doctor' command output table and summary."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    items, findings = run_doctor_checks(
        project_root=project_root,
        profile=pf,
        report_dir_override=report_dir_override,
    )

    rows = [
        [
            item.check_id,
            item.component,
            item.status,
            item.details,
            item.next_step,
        ]
        for item in items
    ]

    counts: dict[str, int] = {"PASS": 0, "WARNING": 0, "ERROR": 0, "UNSUPPORTED": 0}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1

    lines = [
        st.header("APPLICATION HEALTH CHECK (DOCTOR)"),
        f"OS / Version: {pf.display_label} | Execution mode: Read-only | Scope: Local\n",
        format_table(
            headers=["ID", "Component", "State", "Details", "Recommended Action"],
            rows=rows,
            max_col_width=52,
        ),
        "",
        (
            f"Summary: PASS={counts['PASS']} | WARNING={counts['WARNING']} | "
            f"ERROR={counts['ERROR']} | UNSUPPORTED={counts['UNSUPPORTED']}"
        ),
        (
            "Note: 'doctor' evaluates LINUY runtime readiness and permission boundaries only. "
            "A healthy application check does NOT imply that the host computer is free of security risks."
        ),
    ]
    return "\n".join(lines), findings


def run_audit_checks(profile: PlatformProfile | None = None) -> list[Finding]:
    """Dispatch read-only host configuration and permission audit checks for the active OS."""
    from sentinel.checks.linux import run_linux_audit_checks
    from sentinel.checks.windows import run_windows_audit_checks

    pf = profile or detect_platform()
    if pf.os_family == "Linux":
        return run_linux_audit_checks(platform_label=pf.display_label)
    if pf.os_family == "Windows":
        return run_windows_audit_checks(platform_label=pf.display_label)

    return [
        Finding(
            finding_id="AUD-UNSUP-001",
            rule_id="AUD-OS-UNSUPPORTED",
            title="Host Configuration Audit",
            severity=Severity.INFO.value,
            status=FindingStatus.UNSUPPORTED.value,
            platform=pf.display_label,
            description=f"Platform-specific host audit checks are not supported on '{pf.os_family}'.",
            evidence=f"os_family={pf.os_family}",
            detection_rationale="Checked detected OS family against supported targets (Linux, Windows).",
            remediation="Run on Linux or Windows 10/11 for native host configuration audits.",
            timestamp=utc_now_iso(),
            limitations="Host configuration checks are specific to Linux and Windows.",
            inspected_item="OS Family",
            why_it_matters="Avoids applying inaccurate security baselines to unsupported operating systems.",
            determination_method="Evaluated PlatformProfile.os_family.",
        )
    ]


def render_audit_command(
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
) -> tuple[str, list[Finding]]:
    """Execute and render the 'audit' command with detailed rationale, evidence, and limitations."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    findings = run_audit_checks(pf)

    summary_rows = [
        [
            f.finding_id,
            f.rule_id,
            f.status,
            f.severity,
            f.title,
        ]
        for f in findings
    ]

    lines = [
        st.header("READ-ONLY DEFENSIVE SYSTEM AUDIT"),
        f"OS / Version: {pf.display_label} | Execution mode: Read-only | Scope: Local\n",
        format_table(
            headers=["ID", "Rule ID", "Status", "Severity", "Check Title"],
            rows=summary_rows,
            max_col_width=52,
        ),
        st.section("Detailed Audit Evidence & Investigation Guidance"),
    ]

    for f in findings:
        lines.append(
            f"\n{st.format_status(f.status)} {f.finding_id} -- {f.title} (Severity: {st.format_severity(f.severity)})"
        )
        detail_kv = [
            ("What Is Inspected", f.inspected_item or f.title),
            ("Why It Matters", f.why_it_matters or f.description),
            ("How Determined", f.determination_method or f.detection_rationale),
            ("Observed Result", f.description),
            ("Supporting Evidence", f.evidence),
            ("Limitations", f.limitations),
            ("Investigate Next", f.remediation),
        ]
        lines.append(format_kv_block(detail_kv, indent=4))

    return "\n".join(lines), findings
