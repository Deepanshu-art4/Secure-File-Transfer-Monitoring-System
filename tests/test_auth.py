"""
Automated Security & Functional Test Suite for Authentication and RBAC.
Tests registration, credential validation, JWT token issuance, session introspection, and RBAC privilege barriers.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.main import app
from backend.core.database import SessionLocal
from backend.models import User, AuditLog

client = TestClient(app)


def test_system_health():
    """Verify system health endpoint responds with HEALTHY status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "Secure File Transfer" in data["service"]


def test_user_registration_and_duplicate_prevention():
    """Verify user registration and strict rejection of duplicate usernames."""
    unique_user = "test_cadet_01"
    unique_email = "cadet01@soc.local"

    # Clean up if leftover from previous test run
    session = SessionLocal()
    session.query(User).filter((User.username == unique_user) | (User.email == unique_email)).delete()
    session.commit()
    session.close()

    # 1. Valid Registration
    reg_payload = {
        "username": unique_user,
        "email": unique_email,
        "password": "SecurePassword123!"
    }
    response = client.post("/api/auth/register", json=reg_payload)
    assert response.status_code == 201, f"Registration failed: {response.text}"
    data = response.json()
    assert data["username"] == unique_user
    assert data["email"] == unique_email
    assert data["role"] == "user"  # Enforced USER role
    assert data["is_active"] is True

    # 2. Duplicate Username Rejection
    dup_response = client.post("/api/auth/register", json=reg_payload)
    assert dup_response.status_code == 400
    assert "already taken" in dup_response.json()["detail"]


def test_login_and_token_generation():
    """Verify login authentication flow for Admin, Analyst, and User accounts."""
    # 1. Admin Login
    admin_res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "AdminPassword@2026"
    })
    assert admin_res.status_code == 200
    admin_data = admin_res.json()
    assert "access_token" in admin_data
    assert admin_data["role"] == "admin"
    assert admin_data["token_type"] == "bearer"

    # 2. Analyst Login
    analyst_res = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "AnalystPassword@2026"
    })
    assert analyst_res.status_code == 200
    assert analyst_res.json()["role"] == "analyst"

    # 3. User Login
    user_res = client.post("/api/auth/login", json={
        "username": "user1",
        "password": "UserPassword@2026"
    })
    assert user_res.status_code == 200
    assert user_res.json()["role"] == "user"

    # 4. Invalid Password Rejection
    bad_res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "WrongAttackerPassword!"
    })
    assert bad_res.status_code == 401
    assert "Invalid username or password" in bad_res.json()["detail"]


def test_auth_me_introspection():
    """Verify /api/auth/me returns identity claims with valid token and rejects unauthorized requests."""
    # 1. Missing Token -> 401
    unauth_res = client.get("/api/auth/me")
    assert unauth_res.status_code == 401

    # 2. Tampered Token -> 401
    tampered_res = client.get("/api/auth/me", headers={"Authorization": "Bearer fake.tampered.token"})
    assert tampered_res.status_code == 401

    # 3. Valid User Token -> 200
    login_res = client.post("/api/auth/login", json={
        "username": "user1",
        "password": "UserPassword@2026"
    })
    token = login_res.json()["access_token"]

    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "user1"
    assert me_data["role"] == "user"


def test_rbac_privilege_barriers():
    """Verify Role-Based Access Control restricts /api/users to Admin only."""
    # Obtain user token
    user_token = client.post("/api/auth/login", json={
        "username": "user1",
        "password": "UserPassword@2026"
    }).json()["access_token"]

    # Obtain analyst token
    analyst_token = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "AnalystPassword@2026"
    }).json()["access_token"]

    # Obtain admin token
    admin_token = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "AdminPassword@2026"
    }).json()["access_token"]

    # 1. Standard user attempting to list all users -> 403 Forbidden
    user_access = client.get("/api/users", headers={"Authorization": f"Bearer {user_token}"})
    assert user_access.status_code == 403
    assert "Access forbidden" in user_access.json()["detail"]

    # 2. Analyst attempting to list all users -> 403 Forbidden (Only Admin manages users)
    analyst_access = client.get("/api/users", headers={"Authorization": f"Bearer {analyst_token}"})
    assert analyst_access.status_code == 403

    # 3. Admin accessing user list -> 200 OK
    admin_access = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_access.status_code == 200
    data = admin_access.json()
    assert data["total"] >= 3
    assert any(u["username"] == "admin" for u in data["items"])


def test_logout_and_audit_trail():
    """Verify logout records an immutable audit entry."""
    login_res = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "AnalystPassword@2026"
    })
    token = login_res.json()["access_token"]

    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Successfully logged out"

    # Verify audit log was recorded in database
    session = SessionLocal()
    audit_entry = session.query(AuditLog).filter(
        AuditLog.action == "USER_LOGOUT",
        AuditLog.username == "analyst"
    ).order_by(AuditLog.id.desc()).first()
    assert audit_entry is not None
    assert audit_entry.status == "SUCCESS"
    session.close()


if __name__ == "__main__":
    pytest.main(["-v", "tests/test_auth.py"])
