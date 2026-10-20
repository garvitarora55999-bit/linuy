"""Read-only process inspection ('processes').

Implements Part F (Section 13):
- Displays PID, Process name, Executable path (where accessible), Process owner
  (where available), State, and Memory (RSS).
- Uses psutil when available, with native /proc (Linux) and allowlisted tasklist
  (Windows) read-only fallbacks.
- Gracefully handles inaccessible processes, processes terminating mid-inspection,
  and permission errors.
- Strictly avoids collecting environment variables or command-line arguments that
  may contain credentials or tokens.
- Never terminates, suspends, injects into, or modifies processes.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import os
from pathlib import Path

from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import TerminalStyle, format_table
from sentinel.utils.validation import (
    read_bounded_file,
    run_allowlisted_command,
    sanitize_output_text,
)


@dataclass(frozen=True)
class ProcessRecord:
    """Normalized read-only process metadata (excluding cmdline and environment)."""

    pid: int
    name: str
    owner: str
    exe_path: str
    state: str
    rss_kb: int | None
    evidence_source: str


def _uid_to_username(uid: int) -> str:
    try:
        import pwd

        return sanitize_output_text(pwd.getpwuid(uid).pw_name, 64)
    except Exception:
        return f"uid:{uid}"


def collect_processes_psutil() -> tuple[list[ProcessRecord], list[str], int]:
    """Collect running processes via psutil without reading cmdline or environ."""
    import psutil  # type: ignore

    records: list[ProcessRecord] = []
    limitations: list[str] = []
    restricted_count = 0

    for proc in psutil.process_iter(["pid", "name", "username", "status", "memory_info"]):
        try:
            info = proc.info
            pid = int(info.get("pid") or proc.pid)
            name = sanitize_output_text(info.get("name") or "unknown", 64)
            owner = sanitize_output_text(info.get("username") or "restricted", 64)
            state = sanitize_output_text(info.get("status") or "running", 32)
            mem = info.get("memory_info")
            rss_kb = int(getattr(mem, "rss", 0) // 1024) if mem is not None else None
            try:
                exe_raw = proc.exe()
                exe_path = sanitize_output_text(exe_raw or "unavailable", 120)
            except (psutil.AccessDenied, PermissionError):
                exe_path = "<permission denied>"
                restricted_count += 1
            except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                exe_path = "<unavailable>"

            records.append(
                ProcessRecord(
                    pid=pid,
                    name=name,
                    owner=owner,
                    exe_path=exe_path,
                    state=state,
                    rss_kb=rss_kb,
                    evidence_source="psutil",
                )
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            # Process terminated during iteration; skip safely.
            continue
        except (psutil.AccessDenied, PermissionError):
            restricted_count += 1
            continue

    if restricted_count > 0:
        limitations.append(
            f"Executable path or metadata was restricted on {restricted_count} process(es) owned by other users/system."
        )
    limitations.append(
        "Command-line arguments and process environment variables are intentionally omitted to protect credentials."
    )
    return sorted(records, key=lambda r: r.pid), limitations, restricted_count


def collect_processes_linux_proc(proc_root: Path = Path("/proc")) -> tuple[list[ProcessRecord] | None, list[str], int]:
    """Collect running processes on Linux directly from /proc/<pid> in read-only mode."""
    limitations: list[str] = []
    restricted_count = 0

    if not proc_root.is_dir():
        limitations.append(f"Procfs directory {proc_root} is not available.")
        return None, limitations, 0

    records: list[ProcessRecord] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError as exc:
        limitations.append(f"Cannot list {proc_root}: {exc.strerror or 'OS error'}.")
        return None, limitations, 0

    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        status_file = entry / "status"
        comm_file = entry / "comm"
        exe_link = entry / "exe"

        name = "unknown"
        owner = "unknown"
        state = "unknown"
        rss_kb: int | None = None

        try:
            if comm_file.is_file():
                name = sanitize_output_text(
                    read_bounded_file(comm_file, max_bytes=4096, allow_symlinks=False).strip(), 64
                )
            if status_file.is_file():
                status_text = read_bounded_file(status_file, max_bytes=65536, allow_symlinks=False)
                for line in status_text.splitlines():
                    if line.startswith("Name:") and name == "unknown":
                        name = sanitize_output_text(line.partition(":")[2].strip(), 64)
                    elif line.startswith("State:"):
                        state = sanitize_output_text(line.partition(":")[2].strip(), 32)
                    elif line.startswith("Uid:"):
                        parts = line.partition(":")[2].split()
                        if parts and parts[0].isdigit():
                            owner = _uid_to_username(int(parts[0]))
                    elif line.startswith("VmRSS:"):
                        parts = line.partition(":")[2].split()
                        if parts and parts[0].isdigit():
                            rss_kb = int(parts[0])
        except (FileNotFoundError, ProcessLookupError):
            # Process exited during inspection
            continue
        except PermissionError:
            restricted_count += 1
            owner = "<permission denied>"
        except (OSError, ValueError):
            continue

        try:
            target = os.readlink(exe_link)
            exe_path = sanitize_output_text(target, 120)
        except PermissionError:
            exe_path = "<permission denied>"
            restricted_count += 1
        except (FileNotFoundError, ProcessLookupError, OSError):
            exe_path = "<kernel thread or unavailable>"

        records.append(
            ProcessRecord(
                pid=pid,
                name=name,
                owner=owner,
                exe_path=exe_path,
                state=state,
                rss_kb=rss_kb,
                evidence_source="/proc",
            )
        )

    if restricted_count > 0:
        limitations.append(
            f"Executable path (/proc/<pid>/exe) was permission-restricted on {restricted_count} process(es) "
            "(normal for non-root users or kernel threads)."
        )
    limitations.append(
        "Command-line arguments (/proc/<pid>/cmdline) and environment variables (/proc/<pid>/environ) "
        "are intentionally never read to prevent credential exposure."
    )
    return sorted(records, key=lambda r: r.pid), limitations, restricted_count


def parse_windows_tasklist_csv(stdout: str) -> list[ProcessRecord]:
    """Parse output of 'tasklist /FO CSV /V' safely."""
    records: list[ProcessRecord] = []
    reader = csv.reader(io.StringIO(stdout))
    rows = list(reader)
    if not rows:
        return records

    for idx, row in enumerate(rows):
        if not row or len(row) < 2:
            continue
        if idx == 0 and "image name" in row[0].lower():
            continue
        name = sanitize_output_text(row[0], 64)
        pid_str = row[1].strip()
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        mem_str = row[4] if len(row) > 4 else ""
        digits = "".join(ch for ch in mem_str if ch.isdigit())
        rss_kb = int(digits) if digits else None
        state = sanitize_output_text(row[5], 32) if len(row) > 5 else "Running"
        owner = sanitize_output_text(row[6], 64) if len(row) > 6 else "N/A"
        records.append(
            ProcessRecord(
                pid=pid,
                name=name,
                owner=owner,
                exe_path="(use psutil for full path)",
                state=state,
                rss_kb=rss_kb,
                evidence_source="tasklist",
            )
        )
    return sorted(records, key=lambda r: r.pid)


def collect_processes(
    profile: PlatformProfile | None = None,
    prefer_psutil: bool = True,
) -> tuple[list[ProcessRecord] | None, list[str], int]:
    """Collect running processes across Linux and Windows."""
    pf = profile or detect_platform()
    psutil_error_note = ""
    if prefer_psutil and pf.psutil_available:
        try:
            return collect_processes_psutil()
        except Exception as exc:
            psutil_error_note = f"psutil process query failed ({sanitize_output_text(exc, 80)}); using OS fallback."

    if pf.os_family == "Linux":
        recs, lims, rcount = collect_processes_linux_proc()
        if psutil_error_note:
            lims = [psutil_error_note, *lims]
        return recs, lims, rcount

    if pf.os_family == "Windows":
        res = run_allowlisted_command("tasklist", args=["/FO", "CSV", "/V"], timeout=8.0)
        if not res.ok:
            return (
                None,
                [f"Unable to enumerate Windows processes via tasklist: {res.error_message or 'failed'}."],
                0,
            )
        recs = parse_windows_tasklist_csv(res.stdout)
        lims = [
            "Enumerated via 'tasklist /FO CSV /V' fallback because psutil is not installed.",
            "Command-line arguments and environment variables are intentionally omitted.",
        ]
        return recs, lims, 0

    return None, [f"Process inspection is unsupported on OS '{pf.os_family}' without psutil."], 0


def render_processes_command(
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
    max_display: int = 75,
) -> tuple[str, list[Finding]]:
    """Render 'processes' output table and return normalized Finding."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    records, limitations, restricted_count = collect_processes(pf)
    now = utc_now_iso()

    lines = [
        st.header("PROCESS INSPECTION (READ-ONLY)"),
        f"OS / Version: {pf.display_label} | Execution mode: Read-only | Scope: Local",
    ]

    if records is None:
        lines.append("\n  [ERROR/UNSUPPORTED] Process list could not be retrieved.")
        for lim in limitations:
            lines.append(f"  - {lim}")
        finding = Finding(
            finding_id="PRC-0001",
            rule_id="PROC-ENUM-001",
            title="Local Process Enumeration",
            severity=Severity.LOW.value,
            status=FindingStatus.ERROR.value if pf.os_family in ("Linux", "Windows") else FindingStatus.UNSUPPORTED.value,
            platform=pf.display_label,
            description="Could not retrieve active process table.",
            evidence="records=None",
            detection_rationale="Attempted read-only process table inspection.",
            remediation="Verify /proc availability on Linux or psutil/tasklist availability on Windows.",
            timestamp=now,
            limitations=" | ".join(limitations),
            inspected_item="Local OS process table",
            why_it_matters="Visibility into running processes helps identify unexpected daemons or binaries.",
            determination_method="Read-only inspection of psutil or /proc / tasklist.",
        )
        return "\n".join(lines), [finding]

    displayed = records[:max_display]
    rows = [
        [
            str(r.pid),
            r.name,
            r.owner,
            r.state,
            f"{r.rss_kb} KB" if r.rss_kb is not None else "n/a",
            r.exe_path,
            r.evidence_source,
        ]
        for r in displayed
    ]

    lines.append(f"Total Processes Observed: {len(records)} (Restricted/Kernel Paths: {restricted_count})\n")
    lines.append(
        format_table(
            headers=["PID", "Name", "Owner", "State", "Memory (RSS)", "Executable Path", "Source"],
            rows=rows,
            max_col_width=42,
        )
    )
    if len(records) > max_display:
        lines.append(f"\n  (Showing first {max_display} of {len(records)} processes sorted by PID.)")

    if limitations:
        lines.append(st.section("Privacy & Permission Notes"))
        for lim in limitations:
            lines.append(f"  - {lim}")

    finding = Finding(
        finding_id="PRC-0001",
        rule_id="PROC-ENUM-001",
        title="Local Process Inventory",
        severity=Severity.INFO.value,
        status=FindingStatus.PASS.value,
        platform=pf.display_label,
        description=(
            f"Inspected {len(records)} running local process(es); "
            f"{restricted_count} had restricted or kernel executable paths."
        ),
        evidence=(
            f"total_processes={len(records)}; restricted_paths={restricted_count}; "
            f"source={records[0].evidence_source if records else 'os'}"
        ),
        detection_rationale="Enumerated active PIDs in read-only mode without reading cmdline or environment variables.",
        remediation="Review any unfamiliar binaries running under privileged user accounts.",
        timestamp=now,
        limitations=" | ".join(limitations),
        inspected_item="Active local processes (PID, name, owner, executable link, memory)",
        why_it_matters="Identifies active services and verifies executable locations without exposing process secrets.",
        determination_method="Read-only inspection via psutil or /proc/<pid> / tasklist.",
    )
    return "\n".join(lines), [finding]
