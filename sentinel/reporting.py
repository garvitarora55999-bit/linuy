"""JSON and CSV report generation ('report --format json' and 'report --format csv').

Implements Part G (Section 17):
- Exports actual collected findings from the active session or most recent saved run.
- Refuses to generate fake successful reports when no findings exist.
- Writes strictly inside the designated report directory (preventing path traversal and symlink races).
- Avoids overwriting existing reports by default using atomic O_CREAT | O_EXCL | O_NOFOLLOW creation.
- Ensures report-rendering or write failures clean up any created file so empty or misleading reports are never left behind.
- Neutralizes CSV formula injection (prefixing =, +, -, @, tab, CR with a single quote).
- Redacts sensitive strings before writing.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
from typing import Any, Sequence

from sentinel import __app_name__, __mode__, __scope__, __version__
from sentinel.findings import Finding, FindingStore, utc_now_iso
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import TerminalStyle, format_kv_block
from sentinel.utils.validation import (
    open_safe_report_writer,
    sanitize_csv_cell,
    sanitize_output_text,
)

CSV_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "rule_id",
    "title",
    "severity",
    "status",
    "platform",
    "description",
    "evidence",
    "detection_rationale",
    "remediation",
    "timestamp",
    "limitations",
    "inspected_item",
    "why_it_matters",
    "determination_method",
)


def _generate_unique_report_filename(report_dir: Path, fmt: str) -> str:
    """Generate a non-existing timestamped report filename inside report_dir."""
    ext = fmt.lower().strip()
    if ext not in ("json", "csv"):
        raise ValueError(f"Unsupported report format '{fmt}'. Choose 'json' or 'csv'.")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    base_name = f"sentinel_report_{stamp}.{ext}"
    candidate = report_dir / base_name
    if not candidate.exists() and not candidate.is_symlink():
        return base_name

    for idx in range(1, 1000):
        numbered = f"sentinel_report_{stamp}_{idx:02d}.{ext}"
        cand_num = report_dir / numbered
        if not cand_num.exists() and not cand_num.is_symlink():
            return numbered
    raise FileExistsError("Unable to allocate a unique report filename without overwriting existing files.")


def _serialize_report_content(
    findings: Sequence[Finding],
    clean_fmt: str,
    pf: PlatformProfile,
    meta: dict[str, Any],
) -> str:
    """Render the complete JSON or CSV report payload in memory before touching disk."""
    status_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for f in findings:
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    if clean_fmt == "json":
        payload = {
            "report_metadata": {
                "application": __app_name__,
                "version": __version__,
                "mode": __mode__,
                "scope": __scope__,
                "generated_at": utc_now_iso(),
                "platform": pf.display_label,
                "os_family": pf.os_family,
                "hostname": pf.hostname,
                "findings_source": sanitize_output_text(meta.get("source", "session"), 64),
                "last_command": sanitize_output_text(meta.get("last_command", ""), 80),
                "total_findings": len(findings),
                "status_breakdown": status_counts,
                "severity_breakdown": severity_counts,
            },
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    buf = io.StringIO()
    csv_writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    csv_writer.writerow(CSV_COLUMNS)
    for f in findings:
        f_dict = f.to_dict()
        row = [sanitize_csv_cell(f_dict.get(col, "")) for col in CSV_COLUMNS]
        csv_writer.writerow(row)
    return buf.getvalue()


def export_findings_report(
    findings: Sequence[Finding],
    fmt: str,
    report_dir: Path,
    profile: PlatformProfile | None = None,
    run_metadata: dict[str, Any] | None = None,
    custom_filename: str | None = None,
    allow_overwrite: bool = False,
) -> Path:
    """Write collected findings to a JSON or CSV report inside report_dir using atomic exclusive file creation.

    Pre-renders content and cleans up the target file if any write or rendering error occurs,
    preventing empty or partial report files.
    """
    if not findings:
        raise ValueError(
            "No collected findings available to export. Run an inspection command "
            "(e.g., 'audit', 'doctor', 'users', 'network', 'processes', or 'auth') before generating a report."
        )

    clean_fmt = fmt.lower().strip()
    if clean_fmt not in ("json", "csv"):
        raise ValueError(f"Invalid report format '{fmt}'. Supported formats: json, csv.")

    pf = profile or detect_platform()
    meta = run_metadata or {}

    # Render first so any serialization error fails before creating a file on disk.
    rendered_text = _serialize_report_content(findings, clean_fmt, pf, meta)

    filename = custom_filename or _generate_unique_report_filename(report_dir, clean_fmt)
    target_path, writer_fh = open_safe_report_writer(
        report_dir=report_dir,
        filename=filename,
        allow_overwrite=allow_overwrite,
    )

    try:
        with writer_fh:
            writer_fh.write(rendered_text)
            writer_fh.flush()
    except BaseException:
        try:
            if not os.path.islink(target_path) and target_path.is_file():
                target_path.unlink()
        except OSError:
            pass
        raise

    return target_path


def render_report_command(
    fmt: str,
    store: FindingStore,
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
    custom_filename: str | None = None,
) -> tuple[str, Path | None]:
    """Execute 'report --format <json|csv>' and return formatted terminal output and path."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    findings, meta = store.get_findings(fallback_to_cache=True)

    if not findings:
        msg = (
            f"{st.header('REPORT GENERATION')}\n"
            f"  {st.format_status('ERROR')} Cannot generate a report because no inspection findings have been collected yet.\n"
            "  Run at least one check first (e.g., 'audit', 'doctor', 'users', 'network', 'processes', or 'auth --input ...') "
            "and then run 'report --format json' or 'report --format csv'."
        )
        return msg, None

    try:
        output_path = export_findings_report(
            findings=findings,
            fmt=fmt,
            report_dir=store.report_dir,
            profile=pf,
            run_metadata=meta,
            custom_filename=custom_filename,
            allow_overwrite=False,
        )
    except (ValueError, FileExistsError, PermissionError, OSError) as exc:
        msg = (
            f"{st.header('REPORT GENERATION')}\n"
            f"  {st.format_status('ERROR')} Report export failed: {sanitize_output_text(str(exc), 240)}"
        )
        return msg, None

    kv = [
        ("Format", fmt.upper()),
        ("Output File", str(output_path)),
        ("Findings Exported", str(len(findings))),
        ("Data Source", f"{meta.get('source', 'session')} (last command: {meta.get('last_command', 'n/a')})"),
        ("CSV Formula Protection", "Enabled" if fmt.lower() == "csv" else "N/A (Structured JSON)"),
    ]
    lines = [
        st.header("REPORT GENERATED SUCCESSFULLY"),
        format_kv_block(kv),
    ]
    return "\n".join(lines), output_path
