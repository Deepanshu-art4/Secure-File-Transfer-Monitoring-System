from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User, UserRole, AuditLog
from backend.schemas.audit import AuditLogOut, AuditLogListOut
from backend.api.dependencies import get_current_user

router = APIRouter(prefix="/audit-logs", tags=["Tamper-Evident Audit Trail"])


@router.get("", response_model=AuditLogListOut)
def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    username: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves immutable audit logs.
    - Security Analysts and Administrators have comprehensive platform visibility.
    - Standard Users can only access audit logs pertaining to their own activity.
    """
    query = db.query(AuditLog)

    if current_user.role == UserRole.USER:
        query = query.filter(AuditLog.user_id == current_user.id)
    elif username:
        query = query.filter(AuditLog.username.ilike(f"%{username.strip()}%"))

    if action:
        query = query.filter(AuditLog.action == action.strip())

    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type.strip())

    if status_filter:
        query = query.filter(AuditLog.status == status_filter.strip())

    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()

    return AuditLogListOut(total=total, items=logs)


@router.get("/{log_id}", response_model=AuditLogOut)
def get_audit_log(
    log_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves full details of a specific audit log record."""
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit log entry with ID {log_id} not found"
        )

    if current_user.role == UserRole.USER and log.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this audit log"
        )

    return log
