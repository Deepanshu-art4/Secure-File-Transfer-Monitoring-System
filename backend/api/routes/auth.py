from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.core.security import verify_password, hash_password, create_access_token
from backend.models import User, UserRole, AuditLog
from backend.schemas import Token, UserLogin, UserCreate, UserOut, MessageResponse
from backend.api.dependencies import get_current_user, get_client_ip

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Registers a new standard user account.
    Normal registrations default strictly to the USER role for security.
    """
    client_ip = get_client_ip(request)

    # Check for existing username or email
    existing_user = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing_user:
        if existing_user.username == user_in.username:
            detail = "Username is already taken"
        else:
            detail = "Email is already registered"

        # Log failed registration attempt
        audit = AuditLog(
            username=user_in.username,
            action="USER_REGISTRATION_FAILED",
            resource_type="USER",
            resource_id=user_in.username,
            ip_address=client_ip,
            status="DENIED",
            details_json={"reason": detail, "email": user_in.email}
        )
        db.add(audit)
        db.commit()

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    # Create user with salted bcrypt hash
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=UserRole.USER,  # Always enforce USER role on public registration
        is_active=True
    )
    db.add(new_user)
    db.flush()

    # Log successful registration audit
    audit = AuditLog(
        user_id=new_user.id,
        username=new_user.username,
        action="USER_REGISTERED",
        resource_type="USER",
        resource_id=str(new_user.id),
        ip_address=client_ip,
        status="SUCCESS",
        details_json={"role": new_user.role.value, "email": new_user.email}
    )
    db.add(audit)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
def login(
    login_data: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticates user credentials and issues a signed JWT access token.
    Audits all successful and failed authentication attempts with client IP.
    """
    client_ip = get_client_ip(request)

    # Find user by username or email
    user = db.query(User).filter(
        (User.username == login_data.username) | (User.email == login_data.username)
    ).first()

    # Constant-time password verification check
    if not user or not verify_password(login_data.password, user.hashed_password):
        audit = AuditLog(
            username=login_data.username,
            action="USER_LOGIN_FAILED",
            resource_type="AUTH",
            resource_id=login_data.username,
            ip_address=client_ip,
            status="FAILURE",
            details_json={"reason": "Invalid credentials"}
        )
        db.add(audit)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        audit = AuditLog(
            user_id=user.id,
            username=user.username,
            action="USER_LOGIN_BLOCKED",
            resource_type="AUTH",
            resource_id=str(user.id),
            ip_address=client_ip,
            status="DENIED",
            details_json={"reason": "Account is deactivated"}
        )
        db.add(audit)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive. Please contact your SOC Administrator."
        )

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc)

    # Audit successful login
    audit = AuditLog(
        user_id=user.id,
        username=user.username,
        action="USER_LOGIN_SUCCESS",
        resource_type="AUTH",
        resource_id=str(user.id),
        ip_address=client_ip,
        status="SUCCESS",
        details_json={"role": user.role.value}
    )
    db.add(audit)
    db.commit()

    # Generate JWT token
    token = create_access_token(
        subject=str(user.id),
        claims={
            "username": user.username,
            "role": user.role.value,
            "email": user.email
        }
    )

    return Token(
        access_token=token,
        token_type="bearer",
        role=user.role.value,
        username=user.username
    )


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns identity and role claims for the currently authenticated session.
    """
    return current_user


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logs session termination to the immutable audit trail.
    """
    client_ip = get_client_ip(request)
    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="USER_LOGOUT",
        resource_type="AUTH",
        resource_id=str(current_user.id),
        ip_address=client_ip,
        status="SUCCESS",
        details_json={"role": current_user.role.value}
    )
    db.add(audit)
    db.commit()

    return MessageResponse(message="Successfully logged out")
