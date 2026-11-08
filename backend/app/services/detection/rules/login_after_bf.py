"""Successful Login After Brute Force Detection Rule (MITRE ATT&CK T1078).

Detects a successful authentication event originating from an IP address
that recently executed a brute force attempt within a configurable time window.
"""

from collections import defaultdict
from datetime import timedelta

from app.core.config import settings
from app.core.enums import AlertSeverity
from app.models.security_log import SecurityLog
from app.services.detection.base import BaseDetectionRule, DetectionAlertDraft
from app.services.detection.rules.brute_force import BruteForceRule


class LoginAfterBruteForceRule(BaseDetectionRule):
    """Rule B: Successful Login After Brute Force (T1078)."""

    def __init__(
        self,
        bf_threshold: int | None = None,
        bf_window_minutes: int | None = None,
        success_window_minutes: int | None = None,
    ) -> None:
        self.bf_rule = BruteForceRule(threshold=bf_threshold, window_minutes=bf_window_minutes)
        self.success_window = timedelta(
            minutes=success_window_minutes
            if success_window_minutes is not None
            else settings.SUCCESSFUL_LOGIN_AFTER_BF_WINDOW_MINUTES
        )

    @property
    def rule_id(self) -> str:
        return "RULE-T1078"

    @property
    def name(self) -> str:
        return "Successful Login After Brute Force"

    @property
    def mitre_technique_id(self) -> str:
        return "T1078"

    @property
    def default_severity(self) -> AlertSeverity:
        return AlertSeverity.CRITICAL

    def evaluate(self, logs: list[SecurityLog]) -> list[DetectionAlertDraft]:
        drafts: list[DetectionAlertDraft] = []

        # Step 1: Detect all brute force incidents
        bf_alerts = self.bf_rule.evaluate(logs)
        if not bf_alerts:
            return drafts

        # Step 2: Group successful logins by source_ip
        success_by_ip = defaultdict(list)
        for log in logs:
            if log.event_type == "auth_success" and log.source_ip:
                success_by_ip[log.source_ip].append(log)

        # Step 3: Match successful logins occurring after a brute force from the same IP
        for bf in bf_alerts:
            src_ip = bf.source_ip
            if not src_ip or src_ip not in success_by_ip:
                continue

            successes = success_by_ip[src_ip]
            for success_log in successes:
                # Login must occur at or after the start of brute force and within success_window
                diff = success_log.timestamp - bf.detection_time
                # Also handle case where login occurred just as brute force finished or within window
                if timedelta(seconds=0) <= diff <= self.success_window:
                    user_str = f" as user '{success_log.username}'" if success_log.username else ""
                    description = (
                        f"Account compromise suspected: Successful authentication{user_str} from source IP {src_ip} "
                        f"at {success_log.timestamp.isoformat()}, within {self.success_window.total_seconds() / 60:.0f}m "
                        f"of an established brute force attack detected at {bf.detection_time.isoformat()}."
                    )

                    drafts.append(
                        DetectionAlertDraft(
                            rule_id=self.rule_id,
                            technique_id=self.mitre_technique_id,
                            title=f"Successful Login After Brute Force from {src_ip}",
                            description=description,
                            severity=self.default_severity,
                            source_ip=src_ip,
                            incident_start=bf.incident_start,
                            detection_time=success_log.timestamp,
                            window=self.success_window,
                            event_count=1,
                        )
                    )

        return drafts
