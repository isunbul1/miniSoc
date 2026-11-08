"""Pydantic schemas for /api/v1/stats endpoints."""

from pydantic import BaseModel


class MitreTechniqueStat(BaseModel):
    technique_id: str
    technique_name: str
    count: int


class HourlyLogStat(BaseModel):
    hour: str
    count: int


class StatsSummaryResponse(BaseModel):
    total_logs: int
    total_alerts: int
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    alerts_by_mitre: list[MitreTechniqueStat]
    logs_by_event_type: dict[str, int]
    log_counts_per_hour: list[HourlyLogStat]
