from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User, SecurityEvent, SeverityLevel
from backend.schemas.security_event import SecurityEventOut, SecurityEventListOut
from backend.api.dependencies import require_analyst_or_admin

router = APIRouter(prefix="/events", tags=["Security Events Telemetry"])


@router.get("", response_model=SecurityEventListOut)
def list_security_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    transfer_id: Optional[int] = None,
    rule_id: Optional[int] = None,
    severity: Optional[SeverityLevel] = None,
    event_type: Optional[str] = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Lists security events detected across file transfers.
    Accessible to Security Analysts and Administrators.
    """
    query = db.query(SecurityEvent)

    if transfer_id:
        query = query.filter(SecurityEvent.transfer_id == transfer_id)

    if rule_id:
        query = query.filter(SecurityEvent.rule_id == rule_id)

    if severity:
        query = query.filter(SecurityEvent.severity == severity)

    if event_type:
        query = query.filter(SecurityEvent.event_type.ilike(f"%{event_type.strip()}%"))

    total = query.count()
    events = query.order_by(SecurityEvent.created_at.desc()).offset(skip).limit(limit).all()

    return SecurityEventListOut(total=total, items=events)


@router.get("/{event_id}", response_model=SecurityEventOut)
def get_security_event(
    event_id: int,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Retrieves specific security event details and context telemetry."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID {event_id} not found"
        )
    return event
