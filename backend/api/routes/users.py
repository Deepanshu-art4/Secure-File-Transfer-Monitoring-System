from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import User, UserRole, AuditLog
from backend.schemas import UserOut, UserListOut, UserUpdate, MessageResponse
from backend.api.dependencies import get_current_user, require_admin, get_client_ip

router = APIRouter(prefix="/users", tags=["Users Management"])


@router.get("", response_model=UserListOut)
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    role: Optional[UserRole] = None,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    [Admin Only] Lists all registered users across the platform with pagination and role filtering.
    """
    query = db.query(User)
    if role:
        query = query.filter(User.role == role)

    total = query.count()
    users = query.order_by(User.id.asc()).offset(skip).limit(limit).all()

    return UserListOut(total=total, items=users)


@router.get("/{user_id}", response_model=UserOut)
def get_user_by_id(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves user profile. Users can only access their own profile;
    Admins and Security Analysts can view any profile.
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST] and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have authorization to view other user profiles"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user_status(
    user_id: int,
    update_data: UserUpdate,
    request: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    [Admin Only] Updates user account status or role.
    Logged to the audit trail for security accountability.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    client_ip = get_client_ip(request)
    changes = {}

    if update_data.role is not None and update_data.role != user.role:
        changes["old_role"] = user.role.value
        changes["new_role"] = update_data.role.value
        user.role = update_data.role

    if update_data.is_active is not None and update_data.is_active != user.is_active:
        changes["old_active"] = user.is_active
        changes["new_active"] = update_data.is_active
        user.is_active = update_data.is_active

    if update_data.email is not None and update_data.email != user.email:
        changes["old_email"] = user.email
        changes["new_email"] = update_data.email
        user.email = update_data.email

    audit = AuditLog(
        user_id=current_admin.id,
        username=current_admin.username,
        action="USER_UPDATED",
        resource_type="USER",
        resource_id=str(user.id),
        ip_address=client_ip,
        status="SUCCESS",
        details_json=changes
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    return user
