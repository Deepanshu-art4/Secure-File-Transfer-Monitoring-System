"""
Verification script for Step 3: Database Models, Relationships & Seed Data Integrity.
Tests querying seeded users, password verification, rule retrieval, and creating an incident chain.
"""

import sys
import uuid
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.core.database import SessionLocal
from backend.core.security import verify_password
from backend.models import (
    User, UserRole,
    FileTransfer, TransferStatus, IntegrityStatus, RiskLevel,
    SecurityRule, RuleType, SeverityLevel,
    SecurityEvent,
    Alert, AlertStatus,
    AuditLog
)


def test_models():
    print("[*] Running Step 3 Model & Seed Verification...")
    session = SessionLocal()

    try:
        # 1. Verify Seeded Users and Password Hashing
        admin_user = session.query(User).filter(User.username == "admin").first()
        analyst_user = session.query(User).filter(User.username == "analyst").first()
        std_user = session.query(User).filter(User.username == "user1").first()

        assert admin_user is not None, "Admin user not found"
        assert analyst_user is not None, "Analyst user not found"
        assert std_user is not None, "Standard user not found"

        assert admin_user.role == UserRole.ADMIN, "Admin role mismatch"
        assert analyst_user.role == UserRole.ANALYST, "Analyst role mismatch"
        assert std_user.role == UserRole.USER, "User role mismatch"

        assert verify_password("AdminPassword@2026", admin_user.hashed_password), "Admin password verification failed"
        assert verify_password("AnalystPassword@2026", analyst_user.hashed_password), "Analyst password verification failed"
        assert verify_password("UserPassword@2026", std_user.hashed_password), "User password verification failed"

        print(f"[+] Verified 3 Seeded Users: {admin_user.username} ({admin_user.role.value}), {analyst_user.username} ({analyst_user.role.value}), {std_user.username} ({std_user.role.value})")

        # 2. Verify Configurable Security Rules
        rules = session.query(SecurityRule).all()
        assert len(rules) >= 7, f"Expected at least 7 security rules, got {len(rules)}"
        rule_codes = {r.rule_code for r in rules}
        expected_rules = {
            "RULE_LARGE_FILE", "RULE_OFF_HOURS", "RULE_UNKNOWN_DEST",
            "RULE_EXCESSIVE_TX", "RULE_INSECURE_PROTO", "RULE_INTEGRITY_FAIL",
            "RULE_FAILED_PATTERN"
        }
        assert expected_rules.issubset(rule_codes), f"Missing security rules: {expected_rules - rule_codes}"
        print(f"[+] Verified {len(rules)} Configurable Security Rules in DB: {sorted(list(rule_codes))}")

        # 3. Test Creating a Full Incident Chain (Transfer -> Security Event -> Alert -> Status Update)
        mock_tx_uuid = str(uuid.uuid4())
        mock_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        test_transfer = FileTransfer(
            transfer_uuid=mock_tx_uuid,
            user_id=std_user.id,
            filename="classified_quarterly_report.pdf",
            stored_filename=f"classified_{mock_tx_uuid}.pdf",
            file_size_bytes=65 * 1024 * 1024,  # 65 MB (triggers Large File rule)
            mime_type="application/pdf",
            source_ip="192.168.1.105",
            destination_ip="203.0.113.50",
            destination_label="External Untrusted Endpoint",
            protocol="HTTPS",
            status=TransferStatus.FLAGGED,
            sha256_hash=mock_hash,
            expected_hash=mock_hash,
            integrity_status=IntegrityStatus.VERIFIED,
            transfer_duration_ms=4200,
            risk_score=70,
            risk_level=RiskLevel.HIGH,
            is_quarantined=False
        )
        session.add(test_transfer)
        session.flush()

        large_rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_LARGE_FILE").first()

        event = SecurityEvent(
            transfer_id=test_transfer.id,
            rule_id=large_rule.id if large_rule else None,
            event_type="LARGE_FILE_DETECTED",
            description="Transferred payload (65 MB) exceeded 50 MB threshold",
            severity=SeverityLevel.HIGH,
            weight_applied=20,
            details_json={"file_size_mb": 65, "limit_mb": 50}
        )
        session.add(event)

        test_alert = Alert(
            transfer_id=test_transfer.id,
            user_id=std_user.id,
            title="HIGH RISK: Large Payload Transfer to External Endpoint",
            description="File classified_quarterly_report.pdf triggered Large File threshold rule.",
            severity=SeverityLevel.HIGH,
            risk_score=70,
            status=AlertStatus.OPEN
        )
        session.add(test_alert)
        session.flush()

        print(f"[+] Created Test Transfer ID: {test_transfer.id} (UUID: {test_transfer.transfer_uuid[:8]}...)")
        print(f"[+] Linked Alert ID: {test_alert.id} | Status: {test_alert.status.value}")

        # 4. Test SOC Analyst Triage Workflow (OPEN -> INVESTIGATING -> RESOLVED)
        test_alert.status = AlertStatus.INVESTIGATING
        test_alert.assigned_to = analyst_user.id
        test_alert.analyst_notes = "Investigating payload destination IP. Endpoint belongs to partner auditing firm."
        session.flush()

        assert test_alert.status == AlertStatus.INVESTIGATING
        assert test_alert.assigned_to == analyst_user.id
        print(f"[+] Alert Triage Transition Verified: Status is now {test_alert.status.value} (Assigned to Analyst)")

        # 5. Clean up test record to maintain pristine database state
        session.delete(test_alert)
        session.delete(event)
        session.delete(test_transfer)
        session.commit()
        print("[+] Test incident chain cleaned up successfully.")

        # 6. Verify Audit Logs
        init_audit = session.query(AuditLog).filter(AuditLog.action == "DATABASE_INITIALIZED").first()
        assert init_audit is not None, "Database initialization audit log missing"
        print(f"[+] Verified System Audit Trail: action='{init_audit.action}' | status='{init_audit.status}'")

        print("\n[SUCCESS] ALL STEP 3 DATABASE MODEL & SEED INTEGRITY CHECKS PASSED!")

    except Exception as e:
        session.rollback()
        print(f"[ERROR] Step 3 verification failed: {e}")
        raise e
    finally:
        session.close()


if __name__ == "__main__":
    test_models()
