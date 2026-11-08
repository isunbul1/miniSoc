"""Threat Detection Engine.

Orchestrates the execution of all registered detection rules,
maps alerts to MITRE ATT&CK techniques, and enforces structured incident deduplication.

Structured Incident Key & Deduplication:
- Structured Incident Key: (rule_id, entity/source_ip, incident_start)
- Overlapping Windows: Rules merge overlapping windows for the same entity into a single incident.
- Deduplication: When detection runs again and an OPEN incident exists for the same rule and entity
  whose window overlaps or is within W of the cluster, the existing alert is updated
  (event count, evidence, end time) rather than creating a duplicate alert.
- New Attack: An attack from the same IP occurring after the window has fully passed creates a new alert.
- Description Independence: Deduplication does not depend on description text.
"""

import re
from dataclasses import dataclass
from typing import Sequence

from sqlalchemy.orm import Session

from app.core.enums import AlertStatus
from app.models.mitre_technique import MitreTechnique
from app.models.security_alert import SecurityAlert
from app.models.security_log import SecurityLog
from app.services.detection.base import BaseDetectionRule, DetectionAlertDraft
from app.services.detection.rules import (
    BruteForceRule,
    LoginAfterBruteForceRule,
    PortScanRule,
    SuspiciousPowerShellRule,
)


@dataclass
class DetectionRunSummary:
    """Summary of a threat detection engine execution run."""

    rules_executed: int
    total_alerts_created: int
    alerts_per_rule: dict[str, int]


class DetectionEngine:
    """Modular threat detection engine following the Open/Closed Principle.

    Rules can be dynamically registered or customized without modifying
    the core evaluation and alert persistence pipeline.
    """

    def __init__(
        self,
        db: Session,
        rules: Sequence[BaseDetectionRule] | None = None,
    ) -> None:
        self.db = db
        # If no custom rules provided, register default Phase 4 rules
        self.rules: list[BaseDetectionRule] = (
            list(rules)
            if rules is not None
            else [
                BruteForceRule(),
                LoginAfterBruteForceRule(),
                PortScanRule(),
                SuspiciousPowerShellRule(),
            ]
        )

    def register_rule(self, rule: BaseDetectionRule) -> None:
        """Register a new detection rule without altering engine code."""
        self.rules.append(rule)

    def run(self) -> DetectionRunSummary:
        """Execute all registered rules against stored security logs.

        Performs:
        1. Retrieval and sorting of logs.
        2. Rule evaluations.
        3. Incident deduplication against existing alerts in database.
        4. Foreign-key resolution for MITRE technique codes.
        5. Atomic persistence of new SecurityAlert records.
        """
        logs = self.db.query(SecurityLog).order_by(SecurityLog.timestamp).all()

        # Cache MITRE technique code -> DB ID mapping
        mitre_cache: dict[str, int] = {}
        for tech in self.db.query(MitreTechnique).all():
            mitre_cache[tech.technique_id] = tech.id

        # Query active alerts (status 'open' OR 'investigating') from the database
        active_alerts = (
            self.db.query(SecurityAlert)
            .filter(
                SecurityAlert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING])
            )
            .all()
        )

        alerts_per_rule: dict[str, int] = {rule.rule_id: 0 for rule in self.rules}
        new_alerts: list[SecurityAlert] = []

        for rule in self.rules:
            drafts: list[DetectionAlertDraft] = rule.evaluate(logs)
            for draft in drafts:
                mitre_db_id = mitre_cache.get(draft.technique_id)

                # Check if an active incident (open or investigating) exists for the same rule and entity
                # whose window overlaps or is within W of the draft's cluster
                matching_alert: SecurityAlert | None = None
                for alert in active_alerts:
                    # Match by rule_id; fallback to mitre_technique_id for legacy alerts (without rule_id)
                    if alert.rule_id:
                        if alert.rule_id != draft.rule_id:
                            continue
                    else:
                        if alert.mitre_technique_id != mitre_db_id:
                            continue

                    if (alert.source_ip or "") != (draft.source_ip or ""):
                        continue

                    alert_start = alert.incident_start or alert.detection_time
                    alert_end = alert.detection_time
                    w = draft.window

                    if (draft.incident_start <= alert_end + w) and (
                        draft.detection_time >= alert_start - w
                    ):
                        matching_alert = alert
                        break

                if matching_alert is not None:
                    # Update existing active incident
                    # For PowerShell: append any new command evidence lines, never overwrite earlier evidence
                    if draft.rule_id == "RULE-T1059.001":
                        existing_desc = matching_alert.description or ""
                        new_command_lines = []
                        for line in draft.description.splitlines():
                            clean_l = line.strip()
                            if ("Command:" in clean_l or "indicators:" in clean_l) and clean_l not in existing_desc:
                                new_command_lines.append(clean_l)

                        if new_command_lines:
                            existing_lines = [
                                l.strip()
                                for l in existing_desc.splitlines()
                                if "Command:" in l or "indicators:" in l
                            ]
                            all_command_lines = existing_lines + new_command_lines
                            reindexed = []
                            for idx, cl in enumerate(all_command_lines, start=1):
                                cl_body = re.sub(r"^\[\d+\]\s*", "", cl)
                                reindexed.append(f"[{idx}] {cl_body}")

                            count = len(reindexed)
                            src_label = matching_alert.source_ip or "Unknown"
                            header = (
                                f"Suspicious PowerShell execution detected from source IP {src_label} "
                                f"({count} matched command{'s' if count > 1 else ''}):"
                            )
                            matching_alert.description = f"{header}\n" + "\n".join(reindexed)
                    else:
                        matching_alert.description = draft.description

                    matching_alert.detection_time = max(
                        matching_alert.detection_time, draft.detection_time
                    )
                    # Backfill rule_id on legacy alerts if previously missing
                    if matching_alert.rule_id is None:
                        matching_alert.rule_id = draft.rule_id
                    if draft.incident_start and (
                        matching_alert.incident_start is None
                        or draft.incident_start < matching_alert.incident_start
                    ):
                        matching_alert.incident_start = draft.incident_start
                    if matching_alert.incident_start:
                        matching_alert.incident_key = (
                            f"{matching_alert.rule_id}:{matching_alert.source_ip or 'unknown'}:"
                            f"{matching_alert.incident_start.isoformat()}"
                        )
                    continue

                # Create a new alert for new attack / incident outside the window
                incident_key = (
                    f"{draft.rule_id}:{draft.source_ip or 'unknown'}:{draft.incident_start.isoformat()}"
                    if draft.incident_start
                    else None
                )

                alert = SecurityAlert(
                    title=draft.title,
                    description=draft.description,
                    severity=draft.severity,
                    status=AlertStatus.OPEN,
                    source_ip=draft.source_ip,
                    rule_id=draft.rule_id,
                    incident_start=draft.incident_start,
                    incident_key=incident_key,
                    detection_time=draft.detection_time,
                    mitre_technique_id=mitre_db_id,
                )
                self.db.add(alert)
                new_alerts.append(alert)
                active_alerts.append(alert)
                alerts_per_rule[rule.rule_id] += 1

        self.db.commit()
        for a in new_alerts:
            self.db.refresh(a)

        return DetectionRunSummary(
            rules_executed=len(self.rules),
            total_alerts_created=len(new_alerts),
            alerts_per_rule=alerts_per_rule,
        )
