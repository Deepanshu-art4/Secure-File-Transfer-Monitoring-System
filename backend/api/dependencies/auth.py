from typing import List
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.core.config import settings
from backend.core.database import get_db
from backend.core.security import decode_access_token
from backend.models.user import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def get_client_ip(request: Request) -> str:
    """Extracts client IP address safely, checking proxy headers if present."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates the bearer token and retrieves the current authenticated user.
    Raises HTTP 401 Unauthorized if token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_id_str = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception

    try:
        user_id = int(user_id_str)
    except ValueError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )

    return user


def require_role(allowed_roles: List[UserRole]):
    """
    RBAC authorization dependency generator.
    Enforces that the current authenticated user possesses an authorized role.
    """
    def role_verifier(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of roles {[r.value for r in allowed_roles]}"
            )
        return current_user

    return role_verifier


require_admin = require_role([UserRole.ADMIN])
require_analyst_or_admin = require_role([UserRole.ADMIN, UserRole.ANALYST])
