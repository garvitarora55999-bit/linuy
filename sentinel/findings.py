"""Shared Finding data model and local run-state storage.

Implements Part G (Section 16):
- Finding ID, Rule ID, Title, Severity, Status, Platform, Description,
  Evidence, Detection rationale, Recommended investigation or remediation,
  Timestamp, Limitations.
- Consistent severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL.
- Meaningful result states: PASS, FINDING, REVIEW, ERROR, UNSUPPORTED.
- Never converts ERROR or UNSUPPORTED into PASS.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import stat
from typing import Any, Sequence

from sentinel import resolve_default_report_dir
from sentinel.utils.validation import sanitize_output_text


class Severity(str, Enum):
    """Supported finding severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    """Supported check and finding evaluation states."""

    PASS = "PASS"
    FINDING = "FINDING"
    REVIEW = "REVIEW"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"


VALID_SEVERITIES: frozenset[str] = frozenset(s.value for s in Severity)
VALID_STATUSES: frozenset[str] = frozenset(st.value for st in FindingStatus)


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Finding:
    """Normalized defensive security finding or check result."""

    finding_id: str
    rule_id: str
    title: str
    severity: str
    status: str
    platform: str
    description: str
    evidence: str
    detection_rationale: str
    remediation: str
    timestamp: str
    limitations: str
    inspected_item: str = ""
    why_it_matters: str = ""
    determination_method: str = ""

    def __post_init__(self) -> None:
        sev = str(self.severity).upper().strip()
        stat_val = str(self.status).upper().strip()
        if sev not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{self.severity}'. Must be one of {sorted(VALID_SEVERITIES)}.")
        if stat_val not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{self.status}'. Must be one of {sorted(VALID_STATUSES)}.")
        object.__setattr__(self, "severity", sev)
        object.__setattr__(self, "status", stat_val)
        object.__setattr__(self, "finding_id", sanitize_output_text(self.finding_id, 64))
        object.__setattr__(self, "rule_id", sanitize_output_text(self.rule_id, 64))
        object.__setattr__(self, "title", sanitize_output_text(self.title, 160))
        object.__setattr__(self, "platform", sanitize_output_text(self.platform, 64))
        object.__setattr__(self, "description", sanitize_output_text(self.description, 600))
        object.__setattr__(self, "evidence", sanitize_output_text(self.evidence, 600))
        object.__setattr__(self, "detection_rationale", sanitize_output_text(self.detection_rationale, 600))
        object.__setattr__(self, "remediation", sanitize_output_text(self.remediation, 600))
        object.__setattr__(self, "timestamp", sanitize_output_text(self.timestamp or utc_now_iso(), 40))
        object.__setattr__(self, "limitations", sanitize_output_text(self.limitations, 600))
        object.__setattr__(self, "inspected_item", sanitize_output_text(self.inspected_item, 240))
        object.__setattr__(self, "why_it_matters", sanitize_output_text(self.why_it_matters, 400))
        object.__setattr__(self, "determination_method", sanitize_output_text(self.determination_method, 400))

    def to_dict(self) -> dict[str, Any]:
        """Return a safe dictionary representation for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Reconstruct a Finding from a dictionary."""
        return cls(
            finding_id=str(data.get("finding_id", "FND-0000")),
            rule_id=str(data.get("rule_id", "RULE-UNKNOWN")),
            title=str(data.get("title", "Untitled Check")),
            severity=str(data.get("severity", Severity.INFO.value)),
            status=str(data.get("status", FindingStatus.REVIEW.value)),
            platform=str(data.get("platform", "Unknown")),
            description=str(data.get("description", "")),
            evidence=str(data.get("evidence", "")),
            detection_rationale=str(data.get("detection_rationale", "")),
            remediation=str(data.get("remediation", "")),
            timestamp=str(data.get("timestamp", utc_now_iso())),
            limitations=str(data.get("limitations", "")),
            inspected_item=str(data.get("inspected_item", "")),
            why_it_matters=str(data.get("why_it_matters", "")),
            determination_method=str(data.get("determination_method", "")),
        )


class FindingStore:
    """Stores findings in memory during an interactive session and caches the latest run locally."""

    CACHE_FILENAME = ".last_run_cache.json"
    MAX_CACHE_BYTES = 5 * 1024 * 1024
    MAX_SESSION_FINDINGS = 5000

    def __init__(self, report_dir: Path | None = None) -> None:
        self._findings: list[Finding] = []
        self._counter: int = 0
        self._last_command: str = ""
        self._last_updated: str = ""
        if report_dir is None:
            self.report_dir = resolve_default_report_dir()
        else:
            self.report_dir = Path(report_dir)

    def next_finding_id(self, prefix: str = "FND") -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    def add_findings(
        self,
        findings: Sequence[Finding],
        source_command: str = "inspection",
        persist_cache: bool = True,
    ) -> None:
        """Record findings from an executed check and optionally persist to the local run cache."""
        if not findings:
            return
        self._findings.extend(findings)
        if len(self._findings) > self.MAX_SESSION_FINDINGS:
            self._findings = self._findings[-self.MAX_SESSION_FINDINGS :]
        self._last_command = sanitize_output_text(source_command, 80)
        self._last_updated = utc_now_iso()
        if persist_cache:
            self._save_cache()

    def get_findings(self, fallback_to_cache: bool = True) -> tuple[list[Finding], dict[str, Any]]:
        """Return (findings, metadata). If memory is empty and fallback_to_cache is True, load cache."""
        if self._findings:
            meta = {
                "source": "active_session",
                "last_command": self._last_command,
                "timestamp": self._last_updated or utc_now_iso(),
                "count": len(self._findings),
            }
            return list(self._findings), meta

        if fallback_to_cache:
            cached, meta = self._load_cache()
            if cached:
                return cached, meta

        return [], {"source": "none", "last_command": "", "timestamp": "", "count": 0}

    def clear(self, remove_cache: bool = False) -> None:
        self._findings.clear()
        self._counter = 0
        self._last_command = ""
        self._last_updated = ""
        if remove_cache:
            cache_path = self.report_dir / self.CACHE_FILENAME
            try:
                if not os.path.islink(cache_path) and cache_path.is_file():
                    cache_path.unlink()
            except OSError:
                pass

    def _save_cache(self) -> None:
        try:
            if self.report_dir.is_symlink() or os.path.islink(self.report_dir):
                return
            self.report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            dir_lstat = os.lstat(self.report_dir)
            if stat.S_ISLNK(dir_lstat.st_mode) or not stat.S_ISDIR(dir_lstat.st_mode):
                return
            if hasattr(os, "geteuid"):
                if dir_lstat.st_uid != os.geteuid():
                    return
                if (stat.S_IMODE(dir_lstat.st_mode) & 0o022) != 0:
                    try:
                        os.chmod(self.report_dir, 0o700)
                        dir_lstat = os.lstat(self.report_dir)
                    except OSError:
                        pass
                    if (stat.S_IMODE(dir_lstat.st_mode) & 0o022) != 0:
                        return
            cache_path = self.report_dir / self.CACHE_FILENAME
            if cache_path.is_symlink() or os.path.islink(cache_path):
                return

            payload = {
                "source": "cached_previous_run",
                "last_command": self._last_command,
                "timestamp": self._last_updated or utc_now_iso(),
                "count": len(self._findings),
                "findings": [f.to_dict() for f in self._findings],
            }
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            fd = os.open(str(cache_path), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd_stat = os.fstat(fh.fileno())
                if not stat.S_ISREG(fd_stat.st_mode):
                    return
                if hasattr(os, "geteuid") and fd_stat.st_uid != os.geteuid():
                    return
                if hasattr(os, "fchmod"):
                    try:
                        os.fchmod(fh.fileno(), 0o600)
                    except OSError:
                        pass
                fh.write(json.dumps(payload, indent=2))
        except OSError:
            pass

    def _load_cache(self) -> tuple[list[Finding], dict[str, Any]]:
        """Load cached findings only if directory and file ownership and permissions are restricted."""
        cache_path = self.report_dir / self.CACHE_FILENAME
        try:
            if self.report_dir.is_symlink() or os.path.islink(self.report_dir):
                return [], {}
            dir_lstat = os.lstat(self.report_dir)
            if stat.S_ISLNK(dir_lstat.st_mode) or not stat.S_ISDIR(dir_lstat.st_mode):
                return [], {}
            if hasattr(os, "geteuid"):
                if dir_lstat.st_uid != os.geteuid():
                    return [], {}
                if (stat.S_IMODE(dir_lstat.st_mode) & 0o022) != 0:
                    return [], {}

            if cache_path.is_symlink() or os.path.islink(cache_path):
                return [], {}
            lstat_info = os.lstat(cache_path)
            if not stat.S_ISREG(lstat_info.st_mode) or lstat_info.st_size > self.MAX_CACHE_BYTES:
                return [], {}
            if hasattr(os, "geteuid"):
                if lstat_info.st_uid != os.geteuid():
                    return [], {}
                if (stat.S_IMODE(lstat_info.st_mode) & 0o077) != 0:
                    return [], {}

            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(str(cache_path), flags)
            with os.fdopen(fd, "rb") as fh:
                fd_stat = os.fstat(fh.fileno())
                if not stat.S_ISREG(fd_stat.st_mode) or fd_stat.st_size > self.MAX_CACHE_BYTES:
                    return [], {}
                if lstat_info.st_ino != fd_stat.st_ino or lstat_info.st_dev != fd_stat.st_dev:
                    return [], {}
                if hasattr(os, "geteuid"):
                    if fd_stat.st_uid != os.geteuid():
                        return [], {}
                    if (stat.S_IMODE(fd_stat.st_mode) & 0o077) != 0:
                        return [], {}
                raw_bytes = fh.read(self.MAX_CACHE_BYTES + 1)
                if len(raw_bytes) > self.MAX_CACHE_BYTES:
                    return [], {}

            data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            if not isinstance(data, dict):
                return [], {}
            raw_items = data.get("findings", [])
            if not isinstance(raw_items, list):
                return [], {}
            loaded = [Finding.from_dict(item) for item in raw_items[: self.MAX_SESSION_FINDINGS] if isinstance(item, dict)]
            meta = {
                "source": "cached_previous_run",
                "last_command": sanitize_output_text(data.get("last_command", "previous_cli_run"), 80),
                "timestamp": sanitize_output_text(data.get("timestamp", ""), 40),
                "count": len(loaded),
            }
            return loaded, meta
        except (OSError, json.JSONDecodeError, RecursionError, ValueError, TypeError):
            return [], {}
