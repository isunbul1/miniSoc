"""Pydantic schemas for Threat Detection Engine API."""

from pydantic import BaseModel


class DetectionRunResponse(BaseModel):
    """Response returned after executing the threat detection engine."""

    rules_executed: int
    total_alerts_created: int
    alerts_per_rule: dict[str, int]
