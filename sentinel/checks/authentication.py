"""Authentication-log event normalization and detection engine ('auth --input <file>').

Implements Part F (Section 15) with security & performance remediations:
- O(N) linear-time two-pointer sliding-window detection (Defect A).
- Safe handling of JSON Infinity/NaN and extreme datetime OverflowError (Defect B).
- Accurate PAM authentication failure field extraction for rhost and user (Defect C).
- Strict CRLF/LF/CR record splitting preventing Unicode line-separator log forging (Defect D).
- Dynamic reference-year syslog timestamp inference with year-boundary rollover and
  safe leap/non-leap Feb 29 handling without hardcoded year 2026 (Defect G).
- Zero runtime reliance on 'assert' statements so behavior is identical under python -O (Defect H).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re
from typing import Any, Sequence

from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso
from sentinel.platform_info import PlatformProfile, detect_platform
from sentinel.utils.formatting import TerminalStyle, format_kv_block, format_table
from sentinel.utils.validation import (
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_LINE_LENGTH,
    DEFAULT_MAX_LINES,
    read_validated_input_file,
    sanitize_output_text,
    split_log_lines,
)

# Maximum distinct (username, source_ip) pairs tracked in a single file analysis.
MAX_TRACKED_GROUPS: int = 10_000

_MONTH_MAP: dict[str, int] = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# Bounded, linear-time regexes for standard Linux /var/log/auth.log and /var/log/secure
_SYSLOG_PREFIX_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(\S+)\s+([^:]{1,64}):\s+(.*)$"
)
_SYSLOG_RFC3164_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
_SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S{1,64}) from (\S{1,64})"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S{1,64}) from (\S{1,64})"
)
_SSH_INVALID_USER_RE = re.compile(r"Invalid user (\S{1,64}) from (\S{1,64})")

# Dedicated linear-time PAM extractors so rhost and user are captured regardless of field order or spacing.
_PAM_MARKER_RE = re.compile(r"authentication failure", re.IGNORECASE)
_PAM_RHOST_RE = re.compile(r"(?:^|[\s;])rhost=([^\s;]{1,64})")
_PAM_USER_RE = re.compile(r"(?:^|[\s;])user=([^\s;]{1,64})")


@dataclass(frozen=True)
class NormalizedAuthEvent:
    """Normalized authentication event across Linux syslog, Windows 4624/4625, and JSONL."""

    timestamp: datetime | None
    raw_timestamp: str
    outcome: str  # "FAILURE", "SUCCESS"
    username: str | None
    source_ip: str | None
    event_type: str
    platform: str
    evidence_source: str
    line_number: int
    raw_summary: str


AuthEvent = NormalizedAuthEvent


@dataclass(frozen=True)
class AuthAnalysisSummary:
    """Complete result of analyzing an authentication log file."""

    source_path: str
    analysis_mode: str
    total_records_read: int
    valid_auth_events: int
    failed_events_count: int
    success_events_count: int
    malformed_records_count: int
    truncated_by_limit: bool
    events: tuple[NormalizedAuthEvent, ...]
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]


def parse_timestamp_safe(
    raw_ts: Any,
    reference_time: datetime | None = None,
) -> tuple[datetime | None, str]:
    """Parse ISO-8601 or syslog RFC-3164 timestamp into UTC datetime without inventing values.

    Security & correctness controls:
    - Rejects booleans and non-finite floats (Infinity, NaN).
    - Catches OverflowError on extreme timezone conversions near datetime.min / datetime.max.
    - Infers RFC-3164 syslog year relative to reference_time (defaulting to current UTC time)
      without hardcoding 2026, rolling back 1 year if assigning the reference year would
      place a syslog timestamp more than 24 hours into the future.
    - Rejects Feb 29 in non-leap years safely without raising unhandled exceptions.
    """
    if raw_ts is None or isinstance(raw_ts, bool):
        return None, ""
    if isinstance(raw_ts, (int, float)):
        if not math.isfinite(raw_ts):
            return None, sanitize_output_text(str(raw_ts), 64)
        return None, sanitize_output_text(str(raw_ts), 64)

    ts_str = sanitize_output_text(str(raw_ts).strip(), 64)
    if not ts_str:
        return None, ""

    # 1. Try ISO-8601
    iso_candidate = ts_str
    if iso_candidate.endswith("Z") or iso_candidate.endswith("z"):
        iso_candidate = iso_candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        # Validate that timestamp() conversion does not overflow C/OS time bounds
        _ = dt.timestamp()
        return dt, ts_str
    except (ValueError, OverflowError, OSError):
        pass

    # 2. Try RFC-3164 syslog format: "Oct 18 12:01:05"
    normalized_spaces = " ".join(ts_str.split())
    m_sys = _SYSLOG_RFC3164_TS_RE.match(normalized_spaces)
    if m_sys:
        mon_abbr, day_s, hh_s, mm_s, ss_s = m_sys.groups()
        month = _MONTH_MAP.get(mon_abbr)
        if month is None:
            return None, ts_str
        try:
            day = int(day_s)
            hour = int(hh_s)
            minute = int(mm_s)
            second = int(ss_s)
        except ValueError:
            return None, ts_str

        ref_dt = (
            reference_time.astimezone(timezone.utc)
            if reference_time is not None
            else datetime.now(timezone.utc)
        )
        ref_year = ref_dt.year

        try:
            candidate_dt = datetime(ref_year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            # Handles Feb 29 in a non-leap reference year or invalid calendar days (e.g. Feb 30)
            if month == 2 and day == 29:
                try:
                    prev_leap_dt = datetime(ref_year - 1, month, day, hour, minute, second, tzinfo=timezone.utc)
                    if prev_leap_dt <= ref_dt + timedelta(days=1) and (ref_dt - prev_leap_dt) <= timedelta(days=366):
                        return prev_leap_dt, ts_str
                except ValueError:
                    pass
            return None, ts_str

        # If assigning ref_year places the syslog timestamp > 24h in the future (e.g. reading
        # a Dec 31 log on Jan 1), infer the previous calendar year instead of inventing a future date.
        if candidate_dt > ref_dt + timedelta(days=1):
            try:
                candidate_dt = datetime(ref_year - 1, month, day, hour, minute, second, tzinfo=timezone.utc)
            except ValueError:
                return None, ts_str

        return candidate_dt, ts_str

    return None, ts_str


def _clean_optional_field(val: Any, max_len: int = 64) -> str | None:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, float) and not math.isfinite(val):
        return None
    cleaned = sanitize_output_text(str(val).strip(), max_len)
    if not cleaned or cleaned in ("-", "null", "None", "N/A", ""):
        return None
    return cleaned


def _parse_safe_event_id(raw_id: Any) -> int | None:
    """Safely convert an EventID field to int, rejecting booleans, NaN, and Infinity."""
    if raw_id is None or isinstance(raw_id, bool):
        return None
    if isinstance(raw_id, float):
        if not math.isfinite(raw_id):
            return None
    try:
        val = int(raw_id)
    except (ValueError, TypeError, OverflowError):
        return None
    if val < 0 or val > 1_000_000:
        return None
    return val


def normalize_dict_event(
    record: dict[str, Any],
    line_num: int,
    evidence_source: str,
    reference_time: datetime | None = None,
) -> NormalizedAuthEvent | None:
    """Normalize a JSON object (generic JSONL or Windows Security Event 4624/4625) into NormalizedAuthEvent."""
    if not isinstance(record, dict):
        return None

    event_id_raw = record.get("EventID")
    if event_id_raw is None:
        event_id_raw = record.get("event_id")
    if event_id_raw is None:
        event_id_raw = record.get("Id")
    event_id = _parse_safe_event_id(event_id_raw)

    outcome_raw = str(
        record.get("outcome")
        or record.get("status")
        or record.get("result")
        or record.get("Keywords")
        or ""
    ).strip().upper()

    if event_id == 4625 or outcome_raw in ("FAILURE", "FAILED", "FAIL", "AUDIT_FAILURE", "AUDIT FAILURE"):
        outcome = "FAILURE"
    elif event_id == 4624 or outcome_raw in ("SUCCESS", "SUCCEEDED", "OK", "ACCEPTED", "AUDIT_SUCCESS", "AUDIT SUCCESS"):
        outcome = "SUCCESS"
    else:
        return None

    raw_ts = (
        record.get("timestamp")
        or record.get("TimeCreated")
        or record.get("time")
        or record.get("@timestamp")
    )
    dt, ts_str = parse_timestamp_safe(raw_ts, reference_time=reference_time)

    username = _clean_optional_field(
        record.get("username")
        or record.get("user")
        or record.get("account")
        or record.get("TargetUserName")
    )
    source_ip = _clean_optional_field(
        record.get("source_ip")
        or record.get("src_ip")
        or record.get("ip")
        or record.get("IpAddress")
        or record.get("remote_addr")
    )

    if event_id in (4624, 4625):
        event_type = f"windows_{event_id}"
        platform_str = "Windows"
    else:
        event_type = sanitize_output_text(record.get("event_type") or record.get("service") or "auth_event", 40)
        platform_str = sanitize_output_text(record.get("platform") or "Cross-Platform", 40)

    summary_msg = sanitize_output_text(
        record.get("message")
        or f"type={event_type} outcome={outcome} user={username or 'unknown'} src={source_ip or 'unknown'}",
        180,
    )

    return NormalizedAuthEvent(
        timestamp=dt,
        raw_timestamp=ts_str,
        outcome=outcome,
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        platform=platform_str,
        evidence_source=evidence_source,
        line_number=line_num,
        raw_summary=summary_msg,
    )


def normalize_syslog_line(
    line: str,
    line_num: int,
    evidence_source: str,
    reference_time: datetime | None = None,
) -> tuple[NormalizedAuthEvent | None, bool]:
    """Parse a single Linux /var/log/auth.log or /var/log/secure line.

    Returns (event_or_None, is_malformed).
    """
    m = _SYSLOG_PREFIX_RE.match(line)
    if not m:
        return None, True

    raw_ts, _host, service_tag, message = m.groups()
    dt, ts_str = parse_timestamp_safe(raw_ts, reference_time=reference_time)
    service_clean = sanitize_output_text(service_tag.split("[")[0], 32)

    m_fail = _SSH_FAILED_RE.search(message)
    if m_fail:
        user, ip = m_fail.groups()
        return (
            NormalizedAuthEvent(
                timestamp=dt,
                raw_timestamp=ts_str,
                outcome="FAILURE",
                username=_clean_optional_field(user),
                source_ip=_clean_optional_field(ip),
                event_type=f"{service_clean}_failed_login",
                platform="Linux",
                evidence_source=evidence_source,
                line_number=line_num,
                raw_summary=sanitize_output_text(message, 180),
            ),
            False,
        )

    m_acc = _SSH_ACCEPTED_RE.search(message)
    if m_acc:
        user, ip = m_acc.groups()
        return (
            NormalizedAuthEvent(
                timestamp=dt,
                raw_timestamp=ts_str,
                outcome="SUCCESS",
                username=_clean_optional_field(user),
                source_ip=_clean_optional_field(ip),
                event_type=f"{service_clean}_accepted_login",
                platform="Linux",
                evidence_source=evidence_source,
                line_number=line_num,
                raw_summary=sanitize_output_text(message, 180),
            ),
            False,
        )

    m_inv = _SSH_INVALID_USER_RE.search(message)
    if m_inv:
        user, ip = m_inv.groups()
        return (
            NormalizedAuthEvent(
                timestamp=dt,
                raw_timestamp=ts_str,
                outcome="FAILURE",
                username=_clean_optional_field(user),
                source_ip=_clean_optional_field(ip),
                event_type=f"{service_clean}_invalid_user",
                platform="Linux",
                evidence_source=evidence_source,
                line_number=line_num,
                raw_summary=sanitize_output_text(message, 180),
            ),
            False,
        )

    if _PAM_MARKER_RE.search(message):
        rhost_m = _PAM_RHOST_RE.search(message)
        user_m = _PAM_USER_RE.search(message)
        rhost = _clean_optional_field(rhost_m.group(1)) if rhost_m else None
        user = _clean_optional_field(user_m.group(1)) if user_m else None
        return (
            NormalizedAuthEvent(
                timestamp=dt,
                raw_timestamp=ts_str,
                outcome="FAILURE",
                username=user,
                source_ip=rhost,
                event_type=f"{service_clean}_pam_failure",
                platform="Linux",
                evidence_source=evidence_source,
                line_number=line_num,
                raw_summary=sanitize_output_text(message, 180),
            ),
            False,
        )

    return None, False


def detect_auth_anomalies(
    events: Sequence[NormalizedAuthEvent],
    platform_label: str = "Linux",
    failure_threshold: int = 5,
    window_seconds: int = 300,
    malformed_count: int = 0,
    source_label: str = "imported_log",
) -> list[Finding]:
    """Run deterministic O(N) sliding-window authentication detection rules over normalized events."""
    findings: list[Finding] = []
    now = utc_now_iso()
    finding_seq = 0

    def _next_id() -> str:
        nonlocal finding_seq
        finding_seq += 1
        return f"AUT-{finding_seq:04d}"

    grouped: dict[tuple[str, str], list[NormalizedAuthEvent]] = {}
    for ev in events:
        if ev.username is None and ev.source_ip is None:
            continue
        key = (ev.username or "<unknown_user>", ev.source_ip or "<unknown_ip>")
        if key not in grouped and len(grouped) >= MAX_TRACKED_GROUPS:
            continue
        grouped.setdefault(key, []).append(ev)

    for (uname, src_ip), group_events in sorted(grouped.items()):
        with_ts = sorted(
            [e for e in group_events if e.timestamp is not None],
            key=lambda x: (x.timestamp, x.line_number),  # type: ignore[arg-type]
        )
        without_ts = [e for e in group_events if e.timestamp is None]

        # O(N) two-pointer sliding window over timestamped failures
        failures_list: list[NormalizedAuthEvent] = []
        failure_epochs: list[float] = []
        left_idx = 0
        best_start = 0
        best_end = 0
        best_len = 0
        success_lead: tuple[int, int, NormalizedAuthEvent] | None = None

        for ev in with_ts:
            if ev.timestamp is None:
                continue
            ev_epoch = ev.timestamp.timestamp()

            # Advance left_idx past failures older than window_seconds before ev_epoch
            while left_idx < len(failure_epochs):
                delta = ev_epoch - failure_epochs[left_idx]
                if delta > window_seconds or delta < 0:
                    left_idx += 1
                else:
                    break

            if ev.outcome == "FAILURE":
                failures_list.append(ev)
                failure_epochs.append(ev_epoch)
                curr_len = len(failures_list) - left_idx
                if curr_len > best_len:
                    best_len = curr_len
                    best_start = left_idx
                    best_end = len(failures_list)
            elif ev.outcome == "SUCCESS":
                curr_len = len(failures_list) - left_idx
                if curr_len >= failure_threshold and success_lead is None:
                    success_lead = (left_idx, len(failures_list), ev)

        if best_len >= failure_threshold:
            first_ts = failures_list[best_start].raw_timestamp
            last_ts = failures_list[best_end - 1].raw_timestamp
            lines_list = [
                failures_list[i].line_number
                for i in range(best_start, min(best_end, best_start + 10))
            ]
            sev = Severity.HIGH.value if best_len >= failure_threshold * 2 else Severity.MEDIUM.value
            findings.append(
                Finding(
                    finding_id=_next_id(),
                    rule_id="AUTH-DET-001",
                    title=f"Repeated Failed Logins ({uname} from {src_ip})",
                    severity=sev,
                    status=FindingStatus.FINDING.value,
                    platform=platform_label,
                    description=(
                        f"Investigation lead: observed {best_len} failed authentication attempts "
                        f"for account '{uname}' from source '{src_ip}' within a {window_seconds}s window."
                    ),
                    evidence=(
                        f"source={source_label}; user={uname}; src_ip={src_ip}; "
                        f"failures={best_len}; window={first_ts} to {last_ts}; lines={lines_list}"
                    ),
                    detection_rationale=(
                        f"Grouped failed authentication events by (account, source_ip) and evaluated "
                        f"sliding {window_seconds}s window against threshold={failure_threshold}."
                    ),
                    remediation=(
                        "Investigate source IP reputation, verify whether a user or automated script is "
                        "misconfigured, and review account lockout or rate-limiting controls."
                    ),
                    timestamp=now,
                    limitations=(
                        "Log-derived investigation lead only; does not prove attacker identity or account compromise."
                    ),
                    inspected_item=f"Authentication events in {source_label}",
                    why_it_matters="Bursts of failed logins may indicate password guessing, brute-force activity, or a misconfigured client.",
                    determination_method=f"Sliding {window_seconds}s window count >= {failure_threshold} on normalized events.",
                )
            )

        if success_lead is not None:
            s_start, s_end, succ_ev = success_lead
            prior_count = s_end - s_start
            fail_lines = [
                failures_list[i].line_number
                for i in range(s_start, min(s_end, s_start + 8))
            ]
            findings.append(
                Finding(
                    finding_id=_next_id(),
                    rule_id="AUTH-DET-002",
                    title=f"Successful Login Following Repeated Failures ({uname} from {src_ip})",
                    severity=Severity.HIGH.value,
                    status=FindingStatus.FINDING.value,
                    platform=platform_label,
                    description=(
                        f"Investigation lead: account '{uname}' successfully authenticated from '{src_ip}' "
                        f"at {succ_ev.raw_timestamp} (line {succ_ev.line_number}) after {prior_count} "
                        f"failed attempts within {window_seconds}s."
                    ),
                    evidence=(
                        f"source={source_label}; user={uname}; src_ip={src_ip}; "
                        f"prior_failures={prior_count} (lines {fail_lines}); "
                        f"success_line={succ_ev.line_number} at {succ_ev.raw_timestamp}"
                    ),
                    detection_rationale=(
                        f"Observed SUCCESS event within {window_seconds}s of >= {failure_threshold} "
                        f"FAILURE events sharing matching account and source IP."
                    ),
                    remediation=(
                        "Verify with the account owner whether the login at "
                        f"{succ_ev.raw_timestamp} from {src_ip} was legitimate, and inspect post-login session activity."
                    ),
                    timestamp=now,
                    limitations=(
                        "Could represent a legitimate user mistyping a password multiple times before succeeding; "
                        "treat as an investigation lead requiring human verification."
                    ),
                    inspected_item=f"Authentication sequence for {uname}@{src_ip} in {source_label}",
                    why_it_matters="A successful login immediately after repeated failures is a primary indicator of brute-force or credential-stuffing success.",
                    determination_method="Correlated chronological FAILURE and SUCCESS events within the configured time window.",
                )
            )

        ts_less_fails = [e for e in without_ts if e.outcome == "FAILURE"]
        if len(ts_less_fails) >= failure_threshold:
            findings.append(
                Finding(
                    finding_id=_next_id(),
                    rule_id="AUTH-DET-001",
                    title=f"Repeated Failed Logins Without Timestamps ({uname} from {src_ip})",
                    severity=Severity.LOW.value,
                    status=FindingStatus.REVIEW.value,
                    platform=platform_label,
                    description=(
                        f"Observed {len(ts_less_fails)} failed login records for '{uname}' from '{src_ip}', "
                        "but timestamps were missing so time-window correlation could not be verified."
                    ),
                    evidence=f"user={uname}; src_ip={src_ip}; untimestamped_failures={len(ts_less_fails)}",
                    detection_rationale="Counted failed records missing valid timestamps without fabricating timestamps.",
                    remediation="Inspect the raw log source to verify event timing.",
                    timestamp=now,
                    limitations="Missing timestamps prevent sliding-window rate verification.",
                    inspected_item=f"Untimestamped authentication events in {source_label}",
                    why_it_matters="Repeated failures warrant review even when log timestamps are omitted.",
                    determination_method="Grouped failure count where timestamp=None.",
                )
            )

    if malformed_count > 0:
        findings.append(
            Finding(
                finding_id=_next_id(),
                rule_id="AUTH-PARSE-001",
                title="Malformed or Unrecognized Log Records Skipped",
                severity=Severity.LOW.value,
                status=FindingStatus.REVIEW.value,
                platform=platform_label,
                description=(
                    f"Skipped {malformed_count} malformed, truncated, or unrecognized record(s) while parsing {source_label}."
                ),
                evidence=f"source={source_label}; malformed_records={malformed_count}",
                detection_rationale="Tracked records that failed JSON decoding or syslog grammar validation.",
                remediation="Review the input file format if expected authentication events were not parsed.",
                timestamp=now,
                limitations="Malformed lines are never executed or guessed.",
                inspected_item=f"Record syntax in {source_label}",
                why_it_matters="Corrupted or non-standard log lines can hide events if not reported.",
                determination_method="Strict schema and parser validation.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                finding_id=_next_id(),
                rule_id="AUTH-DET-000",
                title="Authentication Log Threshold Analysis",
                severity=Severity.INFO.value,
                status=FindingStatus.PASS.value,
                platform=platform_label,
                description=(
                    f"Analyzed {len(events)} normalized authentication event(s) from {source_label}; "
                    f"no account/source exceeded failure_threshold={failure_threshold} within {window_seconds}s."
                ),
                evidence=f"source={source_label}; normalized_events={len(events)}; threshold={failure_threshold}",
                detection_rationale="Evaluated AUTH-DET-001 and AUTH-DET-002 across all normalized events.",
                remediation="Continue periodic log review.",
                timestamp=now,
                limitations="Offline log analysis reflects only events present in the supplied file and time window.",
                inspected_item=f"Authentication events in {source_label}",
                why_it_matters="Reviews authentication logs for brute-force bursts and post-failure logins.",
                determination_method=f"Sliding {window_seconds}s window analysis.",
            )
        )

    return findings


def analyze_auth_file(
    input_path: str | Path,
    base_dir: Path | None = None,
    failure_threshold: int = 5,
    window_seconds: int = 300,
    max_size_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    analysis_mode: str = "Imported File Analysis (Offline)",
    reference_time: datetime | None = None,
) -> AuthAnalysisSummary:
    """Validate, atomically read, normalize, and run detection rules on an authentication log file."""
    resolved_path, raw_content = read_validated_input_file(
        user_path=input_path,
        max_size_bytes=max_size_bytes,
        base_dir=base_dir,
    )
    source_name = resolved_path.name

    events: list[NormalizedAuthEvent] = []
    malformed_count = 0
    total_records = 0
    truncated = False

    stripped_content = raw_content.lstrip()
    if stripped_content.startswith("["):
        try:
            parsed_array = json.loads(stripped_content)
            if isinstance(parsed_array, list):
                for idx, item in enumerate(parsed_array, start=1):
                    if idx > max_lines:
                        truncated = True
                        break
                    total_records += 1
                    if isinstance(item, dict):
                        ev = normalize_dict_event(
                            item,
                            idx,
                            source_name,
                            reference_time=reference_time,
                        )
                        if ev is not None:
                            events.append(ev)
                        else:
                            malformed_count += 1
                    else:
                        malformed_count += 1
            else:
                total_records += 1
                malformed_count += 1
        except (json.JSONDecodeError, RecursionError, ValueError, TypeError, OverflowError):
            total_records += 1
            malformed_count += 1
    else:
        for idx, raw_line in enumerate(split_log_lines(raw_content), start=1):
            if idx > max_lines:
                truncated = True
                break
            line_stripped = raw_line.strip(" \t")
            if not line_stripped:
                continue
            total_records += 1
            if len(line_stripped) > max_line_length:
                malformed_count += 1
                continue

            if line_stripped.startswith("{") or resolved_path.suffix.lower() in (".jsonl", ".ndjson"):
                try:
                    obj = json.loads(line_stripped)
                    if isinstance(obj, dict):
                        ev = normalize_dict_event(
                            obj,
                            idx,
                            source_name,
                            reference_time=reference_time,
                        )
                        if ev is not None:
                            events.append(ev)
                        else:
                            malformed_count += 1
                    else:
                        malformed_count += 1
                except (json.JSONDecodeError, RecursionError, ValueError, TypeError, OverflowError):
                    malformed_count += 1
            else:
                ev, is_malformed = normalize_syslog_line(
                    line_stripped,
                    idx,
                    source_name,
                    reference_time=reference_time,
                )
                if is_malformed:
                    malformed_count += 1
                elif ev is not None:
                    events.append(ev)

    failed_count = sum(1 for e in events if e.outcome == "FAILURE")
    success_count = sum(1 for e in events if e.outcome == "SUCCESS")

    limitations = [
        f"Analysis mode: {analysis_mode} (does not perform real-time daemon monitoring).",
        "Detections are investigation leads based on threshold correlation, not definitive proof of compromise.",
        "Missing timestamps, usernames, or IP addresses are preserved as None and never fabricated.",
    ]
    if truncated:
        limitations.append(f"Input exceeded max_lines={max_lines}; analysis truncated at {max_lines} records.")

    findings = detect_auth_anomalies(
        events=events,
        platform_label="Cross-Platform (Auth Log)",
        failure_threshold=failure_threshold,
        window_seconds=window_seconds,
        malformed_count=malformed_count,
        source_label=source_name,
    )

    return AuthAnalysisSummary(
        source_path=str(resolved_path),
        analysis_mode=analysis_mode,
        total_records_read=total_records,
        valid_auth_events=len(events),
        failed_events_count=failed_count,
        success_events_count=success_count,
        malformed_records_count=malformed_count,
        truncated_by_limit=truncated,
        events=tuple(events),
        findings=tuple(findings),
        limitations=tuple(limitations),
    )


def render_auth_command(
    input_file: str | Path | None = None,
    base_dir: Path | None = None,
    failure_threshold: int = 5,
    window_seconds: int = 300,
    profile: PlatformProfile | None = None,
    style: TerminalStyle | None = None,
) -> tuple[str, list[Finding]]:
    """Execute and render 'auth --input <file>' (or report local log access status if no file given)."""
    st = style or TerminalStyle(use_color=False)
    pf = profile or detect_platform()
    now = utc_now_iso()

    if not input_file:
        if pf.os_family == "Linux":
            for candidate in (Path("/var/log/auth.log"), Path("/var/log/secure")):
                if candidate.is_file():
                    try:
                        summary = analyze_auth_file(
                            candidate,
                            failure_threshold=failure_threshold,
                            window_seconds=window_seconds,
                            analysis_mode="Local Read-Only Log Inspection",
                        )
                        return _format_auth_summary(summary, st), list(summary.findings)
                    except (PermissionError, ValueError, OSError) as exc:
                        f_err = Finding(
                            finding_id="AUT-ERR-001",
                            rule_id="AUTH-LOCAL-ACCESS",
                            title="Local Authentication Log Access",
                            severity=Severity.LOW.value,
                            status=FindingStatus.ERROR.value,
                            platform=pf.display_label,
                            description=f"Cannot read local log '{candidate}': {sanitize_output_text(exc, 160)}",
                            evidence=f"path={candidate}",
                            detection_rationale="Checked read permissions on local authentication log.",
                            remediation="Supply an exported log via 'auth --input <file>' or run with read access to /var/log/auth.log.",
                            timestamp=now,
                            limitations="Standard users typically lack read permissions on /var/log/auth.log or journald system logs.",
                        )
                        return (
                            f"{st.header('AUTHENTICATION LOG ANALYSIS')}\n"
                            f"  [ERROR] {f_err.description}\n"
                            f"  Tip: Use 'auth --input samples/auth_events.jsonl' to analyze an exported log file.",
                            [f_err],
                        )
        f_unsup = Finding(
            finding_id="AUT-ERR-001",
            rule_id="AUTH-INPUT-REQUIRED",
            title="Authentication Log Input Required",
            severity=Severity.INFO.value,
            status=FindingStatus.UNSUPPORTED.value,
            platform=pf.display_label,
            description=(
                "No --input log file was specified and no readable default local authentication log was found."
            ),
            evidence=f"os={pf.os_family}; input_file=None",
            detection_rationale="Checked for --input argument and accessible local /var/log/auth.log or /var/log/secure.",
            remediation="Run 'auth --input samples/auth_events.jsonl' (or provide a Linux syslog / Windows 4624/4625 JSON export).",
            timestamp=now,
            limitations="Windows Security Event Logs (4624/4625) require Administrator privileges or an exported file.",
        )
        return (
            f"{st.header('AUTHENTICATION LOG ANALYSIS')}\n"
            f"  [UNSUPPORTED/MISSING INPUT] {f_unsup.description}\n"
            f"  Usage: auth --input <path/to/logfile>",
            [f_unsup],
        )

    try:
        summary = analyze_auth_file(
            input_path=input_file,
            base_dir=base_dir,
            failure_threshold=failure_threshold,
            window_seconds=window_seconds,
            analysis_mode="Imported File Analysis (Offline)",
        )
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        f_err = Finding(
            finding_id="AUT-ERR-001",
            rule_id="AUTH-FILE-VALIDATION",
            title="Authentication Log Input Validation Error",
            severity=Severity.LOW.value,
            status=FindingStatus.ERROR.value,
            platform=pf.display_label,
            description=sanitize_output_text(str(exc), 240),
            evidence=f"input={sanitize_output_text(str(input_file), 120)}",
            detection_rationale="Validated user-supplied --input file path, permissions, and size limit.",
            remediation="Provide a valid, readable regular authentication log file within the 10 MiB size limit.",
            timestamp=now,
            limitations="Rejected before parsing due to validation or permission error.",
        )
        return (
            f"{st.header('AUTHENTICATION LOG ANALYSIS')}\n"
            f"  {st.format_status('ERROR')} {f_err.description}",
            [f_err],
        )

    return _format_auth_summary(summary, st), list(summary.findings)


def _format_auth_summary(summary: AuthAnalysisSummary, st: TerminalStyle) -> str:
    kv = [
        ("Analysis Mode", summary.analysis_mode),
        ("Log Source", Path(summary.source_path).name),
        ("Total Records Read", str(summary.total_records_read)),
        ("Normalized Auth Events", str(summary.valid_auth_events)),
        ("Failed Logon Events", str(summary.failed_events_count)),
        ("Successful Logon Events", str(summary.success_events_count)),
        ("Malformed/Skipped Lines", str(summary.malformed_records_count)),
    ]

    lines = [
        st.header("AUTHENTICATION LOG ANALYSIS"),
        format_kv_block(kv),
        st.section(f"Detection Findings / Investigation Leads ({len(summary.findings)})"),
    ]

    f_rows = [
        [
            f.finding_id,
            f.rule_id,
            f.status,
            f.severity,
            f.title,
            f.description,
        ]
        for f in summary.findings
    ]
    lines.append(
        format_table(
            headers=["ID", "Rule", "Status", "Severity", "Title", "Summary / Lead"],
            rows=f_rows,
            max_col_width=46,
        )
    )

    if summary.events:
        lines.append(st.section(f"Normalized Event Sample (showing up to 15 of {len(summary.events)})"))
        e_rows = [
            [
                str(e.line_number),
                e.raw_timestamp or "<missing>",
                e.outcome,
                e.username or "<missing>",
                e.source_ip or "<missing>",
                e.event_type,
            ]
            for e in summary.events[:15]
        ]
        lines.append(
            format_table(
                headers=["Line", "Timestamp", "Outcome", "Account", "Source IP", "Event Type"],
                rows=e_rows,
                max_col_width=32,
            )
        )

    lines.append(st.section("Limitations & Investigation Notes"))
    for lim in summary.limitations:
        lines.append(f"  - {lim}")

    return "\n".join(lines)
