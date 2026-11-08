"""API routes for Threat Detection Engine operations."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.detection import DetectionRunResponse
from app.services.detection.engine import DetectionEngine

router = APIRouter(prefix="/detection", tags=["detection"])


@router.post("/run", response_model=DetectionRunResponse)
def run_detection(db: Session = Depends(get_db)):
    """Run all threat detection rules over stored security logs.

    Identifies incidents (Brute Force, Login After BF, Port Scan,
    Suspicious PowerShell), correlates with MITRE ATT&CK techniques,
    and creates deduplicated security alerts.
    """
    engine = DetectionEngine(db)
    summary = engine.run()
    return DetectionRunResponse(
        rules_executed=summary.rules_executed,
        total_alerts_created=summary.total_alerts_created,
        alerts_per_rule=summary.alerts_per_rule,
    )
