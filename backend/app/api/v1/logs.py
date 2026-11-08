"""API routes for SecurityLog CRUD operations."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.enums import LogSeverity
from app.db.database import get_db
from app.models.security_log import SecurityLog
from app.schemas.security_log import (
    SecurityLogCreate,
    SecurityLogListResponse,
    SecurityLogResponse,
)
from app.services.log_generator import generate_synthetic_logs
from app.services.log_service import LogService

router = APIRouter(prefix="/logs", tags=["logs"])


class LogGenerateRequest(BaseModel):
    """Optional parameters for synthetic log generation."""

    seed: int | None = 42


class LogGenerateResponse(BaseModel):
    """Response returned upon generating synthetic logs."""

    status: str
    generated_count: int
    seed: int | None


@router.post("/generate", response_model=LogGenerateResponse, status_code=201)
def generate_logs_endpoint(
    req: LogGenerateRequest | None = None,
    db: Session = Depends(get_db),
):
    """Generate synthetic security logs.

    Available ONLY when the environment is 'development'.
    In any other environment, returns HTTP 404.
    """
    if settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=404, detail="Not found")

    seed = req.seed if req is not None else 42
    log_dicts = generate_synthetic_logs(seed=seed)

    for entry in log_dicts:
        db.add(SecurityLog(**entry))
    db.commit()

    return LogGenerateResponse(
        status="success",
        generated_count=len(log_dicts),
        seed=seed,
    )


@router.get("", response_model=SecurityLogListResponse)
def list_logs(
    skip: int = Query(0, ge=0, description="Records to skip"),
    limit: int = Query(25, ge=1, le=100, description="Max records to return"),
    severity: LogSeverity | None = Query(None, description="Filter by severity"),
    event_type: str | None = Query(None, description="Filter by event type"),
    source_ip: str | None = Query(None, description="Filter by source IP"),
    db: Session = Depends(get_db),
):
    """Return a paginated list of security logs."""
    service = LogService(db)
    return service.get_logs(
        skip=skip,
        limit=limit,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
    )


@router.get("/{log_id}", response_model=SecurityLogResponse)
def get_log(log_id: int, db: Session = Depends(get_db)):
    """Return a single security log by ID."""
    service = LogService(db)
    log = service.get_log_by_id(log_id)
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


@router.post("", response_model=SecurityLogResponse, status_code=201)
def create_log(data: SecurityLogCreate, db: Session = Depends(get_db)):
    """Create a new security log entry."""
    service = LogService(db)
    return service.create_log(data)


@router.delete("/{log_id}", status_code=204)
def delete_log(log_id: int, db: Session = Depends(get_db)):
    """Delete a security log by ID."""
    service = LogService(db)
    deleted = service.delete_log(log_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Log not found")
    return None
