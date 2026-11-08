"""Suspicious PowerShell Execution Rule (MITRE ATT&CK T1059.001).

Detects PowerShell command lines containing known obfuscation, download,
execution policy bypass, or encoded command indicators using case-insensitive
pattern matching.
"""

from collections import defaultdict
from datetime import timedelta
import re

from app.core.config import settings
from app.core.enums import AlertSeverity
from app.models.security_log import SecurityLog
from app.services.detection.base import BaseDetectionRule, DetectionAlertDraft

# Abbreviations of -EncodedCommand ordered from longest to shortest
ENCODED_COMMAND_PREFIXES = [
    "encodedcommand",
    "encodedcomman",
    "encodedcomma",
    "encodedcomm",
    "encodedcom",
    "encodedco",
    "encodedc",
    "encoded",
    "encode",
    "encod",
    "enco",
    "enc",
    "en",
    "ec",
    "e",
]

# Process must be powershell.exe or pwsh, case-insensitive, with or without full path and quotes
POWERSHELL_PROC_PATTERN = re.compile(
    r'^\s*["\']?(?:.*[\\/])?(?:powershell|pwsh)(?:\.exe)?["\']?(?:\s|$)',
    re.IGNORECASE,
)


class SuspiciousPowerShellRule(BaseDetectionRule):
    """Rule D: Suspicious PowerShell (T1059.001)."""

    def __init__(
        self,
        indicators: list[str] | None = None,
        window_minutes: int | None = None,
    ) -> None:
        self.indicators = (
            indicators if indicators is not None else settings.SUSPICIOUS_POWERSHELL_INDICATORS
        )
        self.window = timedelta(
            minutes=window_minutes
            if window_minutes is not None
            else settings.POWERSHELL_INCIDENT_WINDOW_MINUTES
        )
        self.proc_pattern = POWERSHELL_PROC_PATTERN

        prefix_pattern = "|".join(ENCODED_COMMAND_PREFIXES)

        patterns = [
            # Any abbreviation of -EncodedCommand starting from -e preceded by whitespace or start of string (?<!\S)
            rf'(?<!\S)-(?:{prefix_pattern})\b',
            # -ExecutionPolicy Bypass and -ep bypass preceded by whitespace or start of string (?<!\S)
            rf'(?<!\S)-(?:executionpolicy|ep)\s+bypass\b',
            # IEX / Invoke-Expression
            r'\b(?:iex|invoke-expression)\b',
            # DownloadString
            r'\bdownloadstring\b',
            # -WindowStyle Hidden preceded by whitespace or start of string (?<!\S)
            rf'(?<!\S)-windowstyle\s+hidden\b',
        ]

        self.compiled_pattern = re.compile("|".join(patterns), re.IGNORECASE)

    @property
    def rule_id(self) -> str:
        return "RULE-T1059.001"

    @property
    def name(self) -> str:
        return "Suspicious PowerShell Execution"

    @property
    def mitre_technique_id(self) -> str:
        return "T1059.001"

    @property
    def default_severity(self) -> AlertSeverity:
        return AlertSeverity.HIGH

    def evaluate(self, logs: list[SecurityLog]) -> list[DetectionAlertDraft]:
        drafts: list[DetectionAlertDraft] = []

        # Step 1: Collect all logs matching PowerShell process and indicators, grouped by source_ip
        matches_by_ip = defaultdict(list)
        for log in logs:
            if not log.command_line:
                continue

            # Process must be PowerShell (powershell.exe or pwsh)
            if not self.proc_pattern.search(log.command_line):
                continue

            raw_matches = self.compiled_pattern.findall(log.command_line)
            if raw_matches:
                clean_matches = [
                    m.strip().lstrip("\"'([|;").strip().lower()
                    for m in raw_matches
                    if m.strip()
                ]
                unique_matches = list(dict.fromkeys(clean_matches))

                cmd_snippet = log.command_line.strip()
                if len(cmd_snippet) > 120:
                    cmd_snippet = cmd_snippet[:117] + "..."

                src_ip = log.source_ip or "Unknown"
                matches_by_ip[src_ip].append(
                    {
                        "log": log,
                        "indicators": unique_matches,
                        "snippet": cmd_snippet,
                    }
                )

        # Step 2: Cluster matched commands within window W into unified incidents per host
        for src_ip, item_list in matches_by_ip.items():
            item_list.sort(key=lambda x: x["log"].timestamp)
            if not item_list:
                continue

            clusters: list[list[dict]] = []
            current_cluster: list[dict] = [item_list[0]]
            current_cluster_end = item_list[0]["log"].timestamp

            for item in item_list[1:]:
                item_ts = item["log"].timestamp
                if item_ts <= current_cluster_end + self.window:
                    current_cluster.append(item)
                    current_cluster_end = max(current_cluster_end, item_ts)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [item]
                    current_cluster_end = item_ts

            if current_cluster:
                clusters.append(current_cluster)

            # Step 3: Format evidence preserving ALL matched commands, timestamps, and indicators
            for cluster in clusters:
                earliest_ts = cluster[0]["log"].timestamp
                latest_ts = cluster[-1]["log"].timestamp
                count = len(cluster)

                entries = [
                    f"[{idx}] {it['log'].timestamp.isoformat()} - indicators: [{', '.join(it['indicators'])}] - Command: '{it['snippet']}'"
                    for idx, it in enumerate(cluster, start=1)
                ]

                header = (
                    f"Suspicious PowerShell execution detected from source IP {src_ip} "
                    f"({count} matched command{'s' if count > 1 else ''}):"
                )
                description = f"{header}\n" + "\n".join(entries)

                drafts.append(
                    DetectionAlertDraft(
                        rule_id=self.rule_id,
                        technique_id=self.mitre_technique_id,
                        title=f"Suspicious PowerShell Command on {src_ip}",
                        description=description,
                        severity=self.default_severity,
                        source_ip=src_ip if src_ip != "Unknown" else None,
                        incident_start=earliest_ts,
                        detection_time=latest_ts,
                        window=self.window,
                        event_count=count,
                    )
                )

        return drafts
