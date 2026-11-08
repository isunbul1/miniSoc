"""Brute Force Detection Rule (MITRE ATT&CK T1110).

Detects repeated authentication failures from the same source IP
within a configurable sliding time window.
"""

from collections import defaultdict
from datetime import timedelta

from app.core.config import settings
from app.core.enums import AlertSeverity
from app.models.security_log import SecurityLog
from app.services.detection.base import BaseDetectionRule, DetectionAlertDraft


class BruteForceRule(BaseDetectionRule):
    """Rule A: Brute Force (T1110)."""

    def __init__(
        self,
        threshold: int | None = None,
        window_minutes: int | None = None,
    ) -> None:
        self.threshold = threshold if threshold is not None else settings.BRUTE_FORCE_THRESHOLD
        self.window = timedelta(
            minutes=window_minutes if window_minutes is not None else settings.BRUTE_FORCE_WINDOW_MINUTES
        )

    @property
    def rule_id(self) -> str:
        return "RULE-T1110"

    @property
    def name(self) -> str:
        return "Brute Force Detection"

    @property
    def mitre_technique_id(self) -> str:
        return "T1110"

    @property
    def default_severity(self) -> AlertSeverity:
        return AlertSeverity.HIGH

    def evaluate(self, logs: list[SecurityLog]) -> list[DetectionAlertDraft]:
        drafts: list[DetectionAlertDraft] = []

        # Filter logs for auth_failure and group by source_ip
        failures_by_ip = defaultdict(list)
        for log in logs:
            if log.event_type == "auth_failure" and log.source_ip:
                failures_by_ip[log.source_ip].append(log)

        for src_ip, ip_logs in failures_by_ip.items():
            ip_logs.sort(key=lambda x: x.timestamp)
            n = len(ip_logs)
            if n < self.threshold:
                continue

            # Step 1: Find all sliding windows meeting threshold
            valid_windows: list[list[SecurityLog]] = []
            for i in range(n):
                w_start = ip_logs[i].timestamp
                w_end = w_start + self.window
                matching = [log for log in ip_logs[i:] if log.timestamp <= w_end]
                if len(matching) >= self.threshold:
                    valid_windows.append(matching)

            if not valid_windows:
                continue

            # Step 2: Merge overlapping windows into unified incident clusters
            merged_clusters: list[list[SecurityLog]] = []
            current_cluster: list[SecurityLog] = list(valid_windows[0])
            current_cluster_end = current_cluster[-1].timestamp

            for win in valid_windows[1:]:
                win_start = win[0].timestamp
                win_end = win[-1].timestamp

                # If the window starts within the active cluster window + W, merge
                if win_start <= current_cluster_end + self.window:
                    # Merge uniquely preserving order
                    existing_keys = {
                        (log.id, log.timestamp) if log.id else log.timestamp
                        for log in current_cluster
                    }
                    for log in win:
                        key = (log.id, log.timestamp) if log.id else log.timestamp
                        if key not in existing_keys:
                            current_cluster.append(log)
                            existing_keys.add(key)
                    current_cluster.sort(key=lambda x: x.timestamp)
                    current_cluster_end = max(current_cluster_end, win_end)
                else:
                    merged_clusters.append(current_cluster)
                    current_cluster = list(win)
                    current_cluster_end = win_end

            if current_cluster:
                merged_clusters.append(current_cluster)

            # Step 3: Emit one alert draft per merged incident cluster
            for cluster in merged_clusters:
                earliest_ts = cluster[0].timestamp
                latest_ts = cluster[-1].timestamp
                usernames = sorted({m.username for m in cluster if m.username})
                user_info = (
                    f" targeting user(s): {', '.join(usernames)}" if usernames else ""
                )

                description = (
                    f"Brute force detected from source IP {src_ip}: {len(cluster)} "
                    f"failed authentication events within {self.window.total_seconds() / 60:.0f}m window "
                    f"(threshold: {self.threshold}) between {earliest_ts.isoformat()} and "
                    f"{latest_ts.isoformat()}{user_info}."
                )

                drafts.append(
                    DetectionAlertDraft(
                        rule_id=self.rule_id,
                        technique_id=self.mitre_technique_id,
                        title=f"Brute Force Detected from {src_ip}",
                        description=description,
                        severity=self.default_severity,
                        source_ip=src_ip,
                        incident_start=earliest_ts,
                        detection_time=latest_ts,
                        window=self.window,
                        event_count=len(cluster),
                    )
                )

        return drafts
