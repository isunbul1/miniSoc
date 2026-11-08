"""API router for SOC statistics and summary metrics."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.enums import AlertSeverity, AlertStatus
from app.db.database import get_db
from app.models.mitre_technique import MitreTechnique
from app.models.security_alert import SecurityAlert
from app.models.security_log import SecurityLog
from app.schemas.stats import HourlyLogStat, MitreTechniqueStat, StatsSummaryResponse

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/summary", response_model=StatsSummaryResponse)
def get_stats_summary(db: Session = Depends(get_db)) -> StatsSummaryResponse:
    """Return high-level SOC statistics and dashboard metrics.

    Calculates aggregated metrics directly in the database rather than from
    paginated lists.
    """
    total_logs = db.query(func.count(SecurityLog.id)).scalar() or 0
    total_alerts = db.query(func.count(SecurityAlert.id)).scalar() or 0

    # Alerts by severity (ensure all severity enum keys are present)
    alerts_by_severity: dict[str, int] = {s.value: 0 for s in AlertSeverity}
    sev_rows = (
        db.query(SecurityAlert.severity, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.severity)
        .all()
    )
    for sev, count in sev_rows:
        sev_key = sev.value if hasattr(sev, "value") else str(sev).lower()
        if sev_key in alerts_by_severity:
            alerts_by_severity[sev_key] = count

    # Alerts by status (ensure all status enum keys are present)
    alerts_by_status: dict[str, int] = {st.value: 0 for st in AlertStatus}
    status_rows = (
        db.query(SecurityAlert.status, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.status)
        .all()
    )
    for st, count in status_rows:
        st_key = st.value if hasattr(st, "value") else str(st).lower()
        if st_key in alerts_by_status:
            alerts_by_status[st_key] = count

    # Alerts by MITRE ATT&CK technique
    mitre_rows = (
        db.query(
            MitreTechnique.technique_id,
            MitreTechnique.technique_name,
            func.count(SecurityAlert.id),
        )
        .join(SecurityAlert, SecurityAlert.mitre_technique_id == MitreTechnique.id)
        .group_by(MitreTechnique.technique_id, MitreTechnique.technique_name)
        .order_by(func.count(SecurityAlert.id).desc())
        .all()
    )
    alerts_by_mitre = [
        MitreTechniqueStat(
            technique_id=row[0],
            technique_name=row[1],
            count=row[2],
        )
        for row in mitre_rows
    ]

    # Logs by event_type
    event_rows = (
        db.query(SecurityLog.event_type, func.count(SecurityLog.id))
        .group_by(SecurityLog.event_type)
        .order_by(func.count(SecurityLog.id).desc())
        .all()
    )
    logs_by_event_type: dict[str, int] = {row[0]: row[1] for row in event_rows}

    # Log counts per hour for the last 24 hours (UTC)
    now_utc = datetime.now(timezone.utc)
    current_hour = now_utc.replace(minute=0, second=0, microsecond=0)
    cutoff = current_hour - timedelta(hours=23)

    # 24 hourly buckets: [current_hour - 23h, ..., current_hour]
    bucket_hours = [cutoff + timedelta(hours=i) for i in range(24)]
    # Map by ISO prefix "YYYY-MM-DDTHH" for deterministic matching
    hourly_counts: dict[str, int] = {
        h.strftime("%Y-%m-%dT%H"): 0 for h in bucket_hours
    }

    recent_logs = (
        db.query(SecurityLog.timestamp)
        .filter(SecurityLog.timestamp >= cutoff)
        .all()
    )
    for (ts,) in recent_logs:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        key = ts.strftime("%Y-%m-%dT%H")
        if key in hourly_counts:
            hourly_counts[key] += 1

    log_counts_per_hour = [
        HourlyLogStat(
            hour=h.strftime("%H:00"),
            count=hourly_counts[h.strftime("%Y-%m-%dT%H")],
        )
        for h in bucket_hours
    ]

    return StatsSummaryResponse(
        total_logs=total_logs,
        total_alerts=total_alerts,
        alerts_by_severity=alerts_by_severity,
        alerts_by_status=alerts_by_status,
        alerts_by_mitre=alerts_by_mitre,
        logs_by_event_type=logs_by_event_type,
        log_counts_per_hour=log_counts_per_hour,
    )
