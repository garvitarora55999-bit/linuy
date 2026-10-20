"""Tests for authentication log normalization, detection rules, malformed records, and input limits."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random
import tempfile
import unittest

from sentinel.checks.authentication import (
    MAX_TRACKED_GROUPS,
    AuthEvent,
    NormalizedAuthEvent,
    analyze_auth_file,
    detect_auth_anomalies,
    parse_timestamp_safe,
    render_auth_command,
)
from sentinel.findings import Finding, FindingStatus, Severity, utc_now_iso


def _reference_detect_auth_anomalies(
    events: list[NormalizedAuthEvent],
    platform_label: str = "Linux",
    failure_threshold: int = 5,
    window_seconds: int = 300,
    malformed_count: int = 0,
    source_label: str = "imported_log",
) -> list[Finding]:
    """Reference implementation of the original O(N^2) sliding-window detector for differential testing."""
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

        failures_window: list[NormalizedAuthEvent] = []
        max_burst_events: list[NormalizedAuthEvent] = []
        success_after_failures_pair: tuple[list[NormalizedAuthEvent], NormalizedAuthEvent] | None = None

        for ev in with_ts:
            if ev.timestamp is None:
                continue
            ev_epoch = ev.timestamp.timestamp()
            failures_window = [
                f
                for f in failures_window
                if f.timestamp is not None and 0 <= (ev_epoch - f.timestamp.timestamp()) <= window_seconds
            ]
            if ev.outcome == "FAILURE":
                failures_window.append(ev)
                if len(failures_window) > len(max_burst_events):
                    max_burst_events = list(failures_window)
            elif ev.outcome == "SUCCESS":
                if len(failures_window) >= failure_threshold and success_after_failures_pair is None:
                    success_after_failures_pair = (list(failures_window), ev)

        if len(max_burst_events) >= failure_threshold:
            first_ts = max_burst_events[0].raw_timestamp
            last_ts = max_burst_events[-1].raw_timestamp
            lines_list = [e.line_number for e in max_burst_events[:10]]
            sev = Severity.HIGH.value if len(max_burst_events) >= failure_threshold * 2 else Severity.MEDIUM.value
            findings.append(
                Finding(
                    finding_id=_next_id(),
                    rule_id="AUTH-DET-001",
                    title=f"Repeated Failed Logins ({uname} from {src_ip})",
                    severity=sev,
                    status=FindingStatus.FINDING.value,
                    platform=platform_label,
                    description=(
                        f"Investigation lead: observed {len(max_burst_events)} failed authentication attempts "
                        f"for account '{uname}' from source '{src_ip}' within a {window_seconds}s window."
                    ),
                    evidence=(
                        f"source={source_label}; user={uname}; src_ip={src_ip}; "
                        f"failures={len(max_burst_events)}; window={first_ts} to {last_ts}; lines={lines_list}"
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

        if success_after_failures_pair is not None:
            prior_fails, succ_ev = success_after_failures_pair
            fail_lines = [e.line_number for e in prior_fails[:8]]
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
                        f"at {succ_ev.raw_timestamp} (line {succ_ev.line_number}) after {len(prior_fails)} "
                        f"failed attempts within {window_seconds}s."
                    ),
                    evidence=(
                        f"source={source_label}; user={uname}; src_ip={src_ip}; "
                        f"prior_failures={len(prior_fails)} (lines {fail_lines}); "
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


class TestAuthenticationAnalysis(unittest.TestCase):
    """Verify event normalization, brute-force burst detection, post-failure login detection, and limits."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.project_root = Path(__file__).resolve().parent.parent

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sample_jsonl_fixture_detections(self) -> None:
        sample_path = self.project_root / "samples" / "auth_events.jsonl"
        summary = analyze_auth_file(sample_path, failure_threshold=5, window_seconds=300)
        self.assertEqual(summary.valid_auth_events, 13)
        self.assertEqual(summary.failed_events_count, 11)
        self.assertEqual(summary.success_events_count, 2)
        self.assertEqual(summary.malformed_records_count, 0)

        rules_triggered = [f.rule_id for f in summary.findings]
        self.assertIn("AUTH-DET-001", rules_triggered)
        self.assertIn("AUTH-DET-002", rules_triggered)

    def test_packaged_sample_lookup_from_arbitrary_directory(self) -> None:
        """Verify 'samples/auth_events.jsonl' resolves via bundled package samples even outside repo root."""
        summary = analyze_auth_file(
            "samples/auth_events.jsonl",
            base_dir=self.root,  # empty temp directory with no local samples/ folder
            failure_threshold=5,
            window_seconds=300,
        )
        self.assertEqual(summary.valid_auth_events, 13)

    def test_sample_linux_syslog_fixture_detections(self) -> None:
        sample_syslog = self.project_root / "samples" / "linux_auth.log"
        summary = analyze_auth_file(sample_syslog, failure_threshold=5, window_seconds=300)
        self.assertEqual(summary.valid_auth_events, 7)
        self.assertEqual(summary.failed_events_count, 5)
        self.assertEqual(summary.success_events_count, 2)
        rules_triggered = [f.rule_id for f in summary.findings]
        self.assertIn("AUTH-DET-001", rules_triggered)
        self.assertIn("AUTH-DET-002", rules_triggered)

    def test_sample_windows_json_fixture_detections(self) -> None:
        sample_win = self.project_root / "samples" / "windows_security_events.json"
        summary = analyze_auth_file(sample_win, failure_threshold=5, window_seconds=300)
        self.assertEqual(summary.valid_auth_events, 6)
        self.assertEqual(summary.failed_events_count, 5)
        self.assertEqual(summary.success_events_count, 1)
        rules_triggered = [f.rule_id for f in summary.findings]
        self.assertIn("AUTH-DET-001", rules_triggered)
        self.assertNotIn("AUTH-DET-002", rules_triggered)

    def test_differential_equivalence_old_vs_new_detector_randomized(self) -> None:
        """Differential test: verify new O(N) sliding window produces identical findings to original algorithm."""
        base_dt = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
        users = ["root", "admin", "alice", "bob", "deploy", None]
        ips = ["198.51.100.10", "203.0.113.5", "192.0.2.44", None]

        for seed in range(25):
            rng = random.Random(seed)
            num_events = rng.randint(60, 250)
            events: list[NormalizedAuthEvent] = []
            cur_offset = 0
            for idx in range(num_events):
                cur_offset += rng.randint(-15, 45)
                has_ts = rng.random() > 0.08
                ts = base_dt + timedelta(seconds=cur_offset) if has_ts else None
                outcome = "FAILURE" if rng.random() < 0.78 else "SUCCESS"
                user = rng.choice(users)
                ip = rng.choice(ips)
                events.append(
                    AuthEvent(
                        timestamp=ts,
                        raw_timestamp=ts.isoformat() if ts else "",
                        outcome=outcome,
                        username=user,
                        source_ip=ip,
                        event_type="ssh_auth",
                        platform="Linux",
                        evidence_source="test",
                        line_number=idx + 1,
                        raw_summary=f"event-{idx}",
                    )
                )

            threshold = rng.choice([3, 5, 8])
            window_sec = rng.choice([60, 180, 300])

            # Only compare via reference when assertions are active, or use detect_auth_anomalies
            ref_findings = _reference_detect_auth_anomalies(
                events,
                platform_label="Linux",
                failure_threshold=threshold,
                window_seconds=window_sec,
            )
            new_findings = detect_auth_anomalies(
                events,
                platform_label="Linux",
                failure_threshold=threshold,
                window_seconds=window_sec,
            )

            self.assertEqual(len(ref_findings), len(new_findings), f"Mismatch count for seed={seed}")
            for rf, nf in zip(ref_findings, new_findings):
                self.assertEqual(rf.finding_id, nf.finding_id)
                self.assertEqual(rf.rule_id, nf.rule_id)
                self.assertEqual(rf.title, nf.title)
                self.assertEqual(rf.severity, nf.severity)
                self.assertEqual(rf.status, nf.status)
                self.assertEqual(rf.description, nf.description)
                self.assertEqual(rf.evidence, nf.evidence)

    def test_non_finite_numbers_and_extreme_dates_do_not_crash(self) -> None:
        """Regression test for Defect B: Infinity/NaN in EventID/timestamp and extreme ISO-8601 boundary dates."""
        edge_file = self.root / "edge_cases.jsonl"
        edge_lines = [
            '{"EventID": Infinity, "TargetUserName": "admin", "IpAddress": "198.51.100.1"}',
            '{"EventID": -Infinity, "TargetUserName": "admin", "IpAddress": "198.51.100.1"}',
            '{"EventID": NaN, "TargetUserName": "admin", "IpAddress": "198.51.100.1"}',
            '{"EventID": 1e400, "TargetUserName": "admin", "IpAddress": "198.51.100.1"}',
            '{"EventID": true, "TargetUserName": "admin", "IpAddress": "198.51.100.1"}',
            '{"outcome": "FAILURE", "username": "u1", "timestamp": Infinity}',
            '{"outcome": "FAILURE", "username": "u2", "timestamp": -Infinity}',
            '{"outcome": "FAILURE", "username": "u3", "timestamp": NaN}',
            '{"outcome": "FAILURE", "username": "u4", "timestamp": 1e300}',
            '{"outcome": "FAILURE", "username": "u5", "timestamp": "9999-12-31T23:59:59-05:00"}',
            '{"outcome": "FAILURE", "username": "u6", "timestamp": "0001-01-01T00:00:00+05:00"}',
            '{"outcome": "FAILURE", "username": "valid_user", "source_ip": "198.51.100.9", "timestamp": "2026-10-18T10:00:00Z"}',
        ]
        edge_file.write_text("\n".join(edge_lines) + "\n", encoding="utf-8")

        summary = analyze_auth_file(edge_file, failure_threshold=5, window_seconds=300)
        # 5 invalid EventID records lack outcome and become malformed; 7 records have valid FAILURE outcome
        self.assertEqual(summary.malformed_records_count, 5)
        self.assertEqual(summary.valid_auth_events, 7)

    def test_pam_authentication_failure_parsing_and_detection(self) -> None:
        """Regression test for Defect C: PAM lines extract rhost and user and reach brute-force detection."""
        pam_log = self.root / "pam_auth.log"
        pam_lines = [
            "Oct 18 10:00:01 host sshd[1001]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.77  user=root",
            "Oct 18 10:00:05 host sshd[1002]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.77  user=root",
            "Oct 18 10:00:10 host sshd[1003]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.77  user=root",
            "Oct 18 10:00:15 host sshd[1004]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.77 user=root",
            "Oct 18 10:00:20 host sudo[1005]: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=198.51.100.77  user=root",
        ]
        pam_log.write_text("\n".join(pam_lines) + "\n", encoding="utf-8")

        summary = analyze_auth_file(pam_log, failure_threshold=5, window_seconds=300)
        self.assertEqual(summary.valid_auth_events, 5)
        self.assertEqual(summary.failed_events_count, 5)
        self.assertEqual(summary.malformed_records_count, 0)
        for ev in summary.events:
            self.assertEqual(ev.username, "root")
            self.assertEqual(ev.source_ip, "198.51.100.77")
            self.assertEqual(ev.outcome, "FAILURE")

        rule_ids = [f.rule_id for f in summary.findings]
        self.assertIn("AUTH-DET-001", rule_ids)

    def test_unicode_line_separators_do_not_forge_log_lines(self) -> None:
        """Regression test for Defect D: Unicode separators (U+2028, U+2029, U+0085) cannot split forged log records."""
        forged_log = self.root / "forged.jsonl"
        payload = (
            '{"timestamp": "2026-10-18T10:00:00Z", "outcome": "FAILURE", '
            '"username": "alice\u2028forged_user\u2029second_forged\x85third", "source_ip": "192.0.2.10"}\n'
        )
        forged_log.write_text(payload, encoding="utf-8")

        summary = analyze_auth_file(forged_log, failure_threshold=5, window_seconds=300)
        self.assertEqual(summary.total_records_read, 1)
        self.assertEqual(summary.valid_auth_events, 1)
        self.assertEqual(summary.malformed_records_count, 0)
        self.assertIsNotNone(summary.events[0].username)
        self.assertNotIn("\u2028", summary.events[0].username or "")
        self.assertNotIn("\u2029", summary.events[0].username or "")
        self.assertNotIn("\x85", summary.events[0].username or "")

    def test_syslog_timestamp_year_inference_and_leap_year_handling(self) -> None:
        """Regression test for Defect G: year-boundary rollover and leap-day handling without hardcoded year."""
        # 1. Year boundary: Dec 31 log line inspected on Jan 1, 2027 resolves to 2026-12-31, not future 2027-12-31
        ref_jan1 = datetime(2027, 1, 1, 0, 10, 0, tzinfo=timezone.utc)
        dt_rollover, raw_roll = parse_timestamp_safe("Dec 31 23:55:10", reference_time=ref_jan1)
        self.assertEqual(raw_roll, "Dec 31 23:55:10")
        self.assertEqual(dt_rollover, datetime(2026, 12, 31, 23, 55, 10, tzinfo=timezone.utc))

        # 2. Leap year Feb 29 when reference time is in leap year 2024
        ref_leap = datetime(2024, 3, 5, 12, 0, 0, tzinfo=timezone.utc)
        dt_leap, _ = parse_timestamp_safe("Feb 29 08:15:00", reference_time=ref_leap)
        self.assertEqual(dt_leap, datetime(2024, 2, 29, 8, 15, 0, tzinfo=timezone.utc))

        # 3. Leap day Feb 29 inspected in Jan 2025 (just after leap year 2024) rolls back to 2024-02-29
        ref_early_2025 = datetime(2025, 1, 10, 12, 0, 0, tzinfo=timezone.utc)
        dt_prev_leap, _ = parse_timestamp_safe("Feb 29 08:15:00", reference_time=ref_early_2025)
        self.assertEqual(dt_prev_leap, datetime(2024, 2, 29, 8, 15, 0, tzinfo=timezone.utc))

        # 4. Leap day Feb 29 in non-leap year 2026 (where neither 2026 nor 2025 is a leap year) returns None safely
        ref_non_leap = datetime(2026, 3, 5, 12, 0, 0, tzinfo=timezone.utc)
        dt_non_leap, raw_non_leap = parse_timestamp_safe("Feb 29 08:15:00", reference_time=ref_non_leap)
        self.assertIsNone(dt_non_leap)
        self.assertEqual(raw_non_leap, "Feb 29 08:15:00")

        # 5. Impossible calendar date Feb 30 -> rejected cleanly without raising ValueError
        dt_bad, _ = parse_timestamp_safe("Feb 30 08:15:00", reference_time=ref_leap)
        self.assertIsNone(dt_bad)

    def test_malformed_records_and_deeply_nested_json_recursion_safety(self) -> None:
        # Deeply nested JSON line (>1500 levels) that triggers Python's RecursionError in json.loads
        deep_nested_line = '{"a":' * 1500 + "1" + "}" * 1500
        mixed_file = self.root / "mixed.jsonl"
        mixed_file.write_text(
            '{"outcome": "FAILURE", "username": "operator"}\n'
            "NOT_VALID_JSON_LINE\n"
            f"{deep_nested_line}\n"
            '{"outcome": "UNKNOWN_OUTCOME", "username": "nobody"}\n',
            encoding="utf-8",
        )
        summary = analyze_auth_file(mixed_file, failure_threshold=3, window_seconds=60)
        self.assertEqual(summary.valid_auth_events, 1)
        self.assertEqual(summary.malformed_records_count, 3)
        ev = summary.events[0]
        self.assertIsNone(ev.timestamp)
        self.assertIsNone(ev.source_ip)
        self.assertEqual(ev.username, "operator")

        rule_ids = [f.rule_id for f in summary.findings]
        self.assertIn("AUTH-PARSE-001", rule_ids)

        # Deeply nested JSON array file starting with '['
        deep_array_file = self.root / "deep_array.json"
        deep_array_file.write_text("[" * 2000 + "]" * 2000, encoding="utf-8")
        arr_summary = analyze_auth_file(deep_array_file)
        self.assertEqual(arr_summary.valid_auth_events, 0)
        self.assertEqual(arr_summary.malformed_records_count, 1)

    def test_oversized_and_symlink_files_rejected(self) -> None:
        big_file = self.root / "oversized.log"
        big_file.write_bytes(b"A" * 2048)
        with self.assertRaises(ValueError):
            analyze_auth_file(big_file, max_size_bytes=1024)

        symlink_file = self.root / "symlink.log"
        symlink_file.symlink_to(big_file)
        with self.assertRaises(ValueError):
            analyze_auth_file(symlink_file)

        out_sym, findings_sym = render_auth_command(input_file=symlink_file, base_dir=self.root)
        self.assertIn("[ERROR]", out_sym)
        self.assertEqual(findings_sym[0].status, "ERROR")

        out, findings = render_auth_command(input_file=big_file, base_dir=self.root)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
