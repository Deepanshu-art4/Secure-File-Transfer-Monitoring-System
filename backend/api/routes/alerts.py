from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User, UserRole, Alert, AlertStatus, SeverityLevel
from backend.schemas.alert import AlertOut, AlertListOut, AlertUpdate
from backend.alerts.alert_manager import AlertManager
from backend.api.dependencies import get_current_user, require_analyst_or_admin

router = APIRouter(prefix="/alerts", tags=["Incident & Alert Management"])


@router.get("", response_model=AlertListOut)
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[AlertStatus] = None,
    severity: Optional[SeverityLevel] = None,
    assigned_to: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists security incident alerts with filtering and pagination.
    - Security Analysts and Admins see global alerts.
    - Standard Users see only incidents involving their account.
    """
    query = db.query(Alert)

    if current_user.role == UserRole.USER:
        query = query.filter(Alert.user_id == current_user.id)
    else:
        if assigned_to is not None:
            query = query.filter(Alert.assigned_to == assigned_to)

    if status:
        query = query.filter(Alert.status == status)

    if severity:
        query = query.filter(Alert.severity == severity)

    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

    return AlertListOut(total=total, items=alerts)


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves full incident report and triage history."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID {alert_id} not found"
        )

    if current_user.role == UserRole.USER and alert.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have authorization to view this security alert"
        )

    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    current_analyst: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    [Analyst/Admin] Transitions incident lifecycle (OPEN -> INVESTIGATING -> RESOLVED / FALSE_POSITIVE),
    assigns incident to analysts, and records investigation findings.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID {alert_id} not found"
        )

    updated_alert = AlertManager.update_alert(
        alert=alert,
        new_status=payload.status,
        analyst=current_analyst,
        analyst_notes=payload.analyst_notes,
        assigned_to=payload.assigned_to,
        db=db
    )

    return updated_alert
