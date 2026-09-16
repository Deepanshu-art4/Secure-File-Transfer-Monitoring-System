"""
Verification script for Step 2: Core Configuration, Security & Database Engine.
Run this script to verify settings, bcrypt hashing, JWT token operations, and database initialization.
"""

import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.core.config import settings
from backend.core.security import hash_password, verify_password, create_access_token, decode_access_token
from backend.core.database import engine, Base, SessionLocal


def test_core():
    print("[*] Running Step 2 Core Verification...")

    # 1. Test Settings
    print(f"[+] Loaded Project Name: {settings.PROJECT_NAME}")
    print(f"[+] Environment: {settings.ENVIRONMENT}")
    print(f"[+] Database URL: {settings.DATABASE_URL}")
    print(f"[+] Allowed Extensions: {settings.allowed_extensions_set}")
    assert settings.PROJECT_NAME == "Secure File Transfer Monitoring System"
    assert "pdf" in settings.allowed_extensions_set
    print("    -> Settings verification PASSED")

    # 2. Test Storage Directories
    settings.ensure_directories_exist(base_dir=ROOT_DIR / "backend")
    print("    -> Storage directories verified / created")

    # 3. Test Bcrypt Password Hashing
    test_pwd = "SuperSecretSecurePassword!2026"
    hashed = hash_password(test_pwd)
    print(f"[+] Hashed Password: {hashed[:20]}...")
    assert verify_password(test_pwd, hashed) is True, "Password verification failed"
    assert verify_password("WrongPassword", hashed) is False, "False positive in password verification"
    print("    -> Bcrypt password hashing & verification PASSED")

    # 4. Test JWT Generation & Decoding
    payload_claims = {"username": "admin", "role": "admin", "email": "admin@soc.local"}
    token = create_access_token(subject="user_1", claims=payload_claims)
    print(f"[+] Generated JWT Token: {token[:25]}...")
    decoded = decode_access_token(token)
    assert decoded is not None, "Failed to decode JWT"
    assert decoded["sub"] == "user_1"
    assert decoded["role"] == "admin"
    print(f"[+] Decoded JWT Subject: {decoded['sub']} | Role: {decoded['role']}")

    # Test invalid token
    invalid_decoded = decode_access_token("invalid.tampered.token")
    assert invalid_decoded is None, "Tampered token should return None"
    print("    -> JWT creation, verification, and tamper detection PASSED")

    # 5. Test Database Engine & Session
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        from sqlalchemy import text
        result = session.execute(text("SELECT 1")).scalar()
        assert result == 1, "Database query failed"
        print(f"[+] Database Engine Ping: {result} (Connected successfully)")
        print("    -> Database connectivity PASSED")
    finally:
        session.close()

    print("\n[SUCCESS] ALL STEP 2 CORE VERIFICATION CHECKS PASSED!")


if __name__ == "__main__":
    test_core()
