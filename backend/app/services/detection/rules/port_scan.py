"""Port Scan Detection Rule (MITRE ATT&CK T1046).

Detects single source IPs connecting to multiple distinct destination ports
within a short sliding time window.
"""

from collections import defaultdict
from datetime import timedelta

from app.core.config import settings
from app.core.enums import AlertSeverity
from app.models.security_log import SecurityLog
from app.services.detection.base import BaseDetectionRule, DetectionAlertDraft


class PortScanRule(BaseDetectionRule):
    """Rule C: Port Scan (T1046)."""

    def __init__(
        self,
        port_threshold: int | None = None,
        window_minutes: int | None = None,
    ) -> None:
        self.port_threshold = (
            port_threshold if port_threshold is not None else settings.PORT_SCAN_PORT_THRESHOLD
        )
        self.window = timedelta(
            minutes=window_minutes if window_minutes is not None else settings.PORT_SCAN_WINDOW_MINUTES
        )

    @property
    def rule_id(self) -> str:
        return "RULE-T1046"

    @property
    def name(self) -> str:
        return "Port Scan Detection"

    @property
    def mitre_technique_id(self) -> str:
        return "T1046"

    @property
    def default_severity(self) -> AlertSeverity:
        return AlertSeverity.MEDIUM

    def evaluate(self, logs: list[SecurityLog]) -> list[DetectionAlertDraft]:
        drafts: list[DetectionAlertDraft] = []

        # Filter logs with valid destination_port and group by source_ip
        logs_by_ip = defaultdict(list)
        for log in logs:
            if log.destination_port is not None and log.source_ip:
                logs_by_ip[log.source_ip].append(log)

        for src_ip, ip_logs in logs_by_ip.items():
            ip_logs.sort(key=lambda x: x.timestamp)
            n = len(ip_logs)
            if n < self.port_threshold:
                continue

            # Step 1: Find all sliding windows meeting port threshold
            valid_windows: list[list[SecurityLog]] = []
            for i in range(n):
                w_start = ip_logs[i].timestamp
                w_end = w_start + self.window
                matching = [log for log in ip_logs[i:] if log.timestamp <= w_end]
                distinct_ports = {
                    l.destination_port for l in matching if l.destination_port is not None
                }
                if len(distinct_ports) >= self.port_threshold:
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

                if win_start <= current_cluster_end + self.window:
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
                distinct_ports = {
                    log.destination_port
                    for log in cluster
                    if log.destination_port is not None
                }
                earliest_ts = cluster[0].timestamp
                latest_ts = cluster[-1].timestamp
                ports_sample = sorted(list(distinct_ports))[:10]

                description = (
                    f"Port scan detected from source IP {src_ip}: {len(distinct_ports)} "
                    f"distinct destination ports targeted within {self.window.total_seconds() / 60:.0f}m window "
                    f"(threshold: {self.port_threshold}) between {earliest_ts.isoformat()} and "
                    f"{latest_ts.isoformat()}. Ports sample: {ports_sample}."
                )

                drafts.append(
                    DetectionAlertDraft(
                        rule_id=self.rule_id,
                        technique_id=self.mitre_technique_id,
                        title=f"Port Scan Detected from {src_ip}",
                        description=description,
                        severity=self.default_severity,
                        source_ip=src_ip,
                        incident_start=earliest_ts,
                        detection_time=latest_ts,
                        window=self.window,
                        event_count=len(distinct_ports),
                    )
                )

        return drafts
