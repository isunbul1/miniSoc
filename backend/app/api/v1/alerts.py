"""API routes for SecurityAlert CRUD operations."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.enums import AlertSeverity, AlertStatus
from app.db.database import get_db
from app.schemas.security_alert import (
    SecurityAlertCreate,
    SecurityAlertListResponse,
    SecurityAlertResponse,
    SecurityAlertUpdate,
)
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=SecurityAlertListResponse)
def list_alerts(
    skip: int = Query(0, ge=0, description="Records to skip"),
    limit: int = Query(25, ge=1, le=100, description="Max records to return"),
    severity: AlertSeverity | None = Query(None, description="Filter by severity"),
    status: AlertStatus | None = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
):
    """Return a paginated list of security alerts."""
    service = AlertService(db)
    return service.get_alerts(
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
    )


@router.get("/{alert_id}", response_model=SecurityAlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Return a single security alert by ID."""
    service = AlertService(db)
    alert = service.get_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("", response_model=SecurityAlertResponse, status_code=201)
def create_alert(data: SecurityAlertCreate, db: Session = Depends(get_db)):
    """Create a new security alert."""
    service = AlertService(db)
    return service.create_alert(data)


@router.patch("/{alert_id}", response_model=SecurityAlertResponse)
def update_alert(
    alert_id: int, data: SecurityAlertUpdate, db: Session = Depends(get_db)
):
    """Partially update an existing security alert."""
    service = AlertService(db)
    alert = service.update_alert(alert_id, data)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.delete("/{alert_id}", status_code=204)
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    """Delete a security alert by ID."""
    service = AlertService(db)
    deleted = service.delete_alert(alert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Alert not found")
    return None
