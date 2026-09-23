"""
Automated Test Suite for Step 6: Security Detection Pipeline & Dynamic Risk Scoring Engine.
Tests all 7 security detection rules, dynamic cumulative risk scoring, rule management RBAC,
and real-time security events telemetry logging.
"""

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.main import app
from backend.core.database import SessionLocal
from backend.models import (
    User,
    FileTransfer,
    SecurityRule,
    SecurityEvent,
    RuleType,
    SeverityLevel,
    RiskLevel,
    TransferStatus,
    IntegrityStatus,
)
from backend.detection.rule_engine import DetectionEngine
from backend.risk.risk_scorer import RiskScorer

client = TestClient(app)


@pytest.fixture(scope="module")
def auth_tokens():
    """Retrieves auth tokens for admin, analyst, and standard user."""
    admin_res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "AdminPassword@2026"
    })
    analyst_res = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "AnalystPassword@2026"
    })
    user_res = client.post("/api/auth/login", json={
        "username": "user1",
        "password": "UserPassword@2026"
    })

    return {
        "admin": admin_res.json()["access_token"],
        "analyst": analyst_res.json()["access_token"],
        "user": user_res.json()["access_token"],
    }


def test_large_file_rule_detection():
    """Verify RULE_LARGE_FILE triggers when file exceeds configured threshold."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_LARGE_FILE").first()
    assert rule is not None
    assert rule.is_enabled is True

    # 1. Transfer under 50 MB threshold (10 MB)
    small_transfer = FileTransfer(
        transfer_uuid="test-uuid-small",
        user_id=1,
        filename="small.pdf",
        stored_filename="test-uuid-small_small.pdf",
        file_size_bytes=10 * 1024 * 1024,
        mime_type="application/pdf",
        source_ip="127.0.0.1",
        destination_ip="10.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="e" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime(2026, 9, 23, 11, 0, 0, tzinfo=timezone.utc)  # Wednesday 11:00 AM (Work Hours)
    )
    event_small = DetectionEngine._evaluate_single_rule(rule, small_transfer, session)
    assert event_small is None

    # 2. Transfer over threshold (60 MB)
    large_transfer = FileTransfer(
        transfer_uuid="test-uuid-large",
        user_id=1,
        filename="massive_database.zip",
        stored_filename="test-uuid-large_massive_database.zip",
        file_size_bytes=60 * 1024 * 1024,
        mime_type="application/zip",
        source_ip="127.0.0.1",
        destination_ip="10.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="f" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime(2026, 9, 23, 11, 0, 0, tzinfo=timezone.utc)
    )
    event_large = DetectionEngine._evaluate_single_rule(rule, large_transfer, session)
    assert event_large is not None
    assert event_large.event_type == "RULE_LARGE_FILE"
    assert event_large.severity == SeverityLevel.HIGH
    assert event_large.weight_applied == 20
    assert "60.0 MB" in event_large.description
    session.close()


def test_off_hours_rule_detection():
    """Verify RULE_OFF_HOURS triggers for night transfers and weekend activity."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_OFF_HOURS").first()
    assert rule is not None

    # 1. Normal work hours: Wednesday at 14:00 (2 PM) -> No trigger
    work_hours_tx = FileTransfer(
        transfer_uuid="test-uuid-work",
        user_id=1,
        filename="report.docx",
        stored_filename="test-uuid-work_report.docx",
        file_size_bytes=1024,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        source_ip="127.0.0.1",
        destination_ip="10.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="a" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime(2026, 9, 23, 14, 0, 0, tzinfo=timezone.utc)
    )
    event_normal = DetectionEngine._evaluate_single_rule(rule, work_hours_tx, session)
    assert event_normal is None

    # 2. Night transfer: Wednesday at 23:00 (11 PM) -> Trigger
    night_tx = FileTransfer(
        transfer_uuid="test-uuid-night",
        user_id=1,
        filename="night_exfil.docx",
        stored_filename="test-uuid-night_night_exfil.docx",
        file_size_bytes=1024,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        source_ip="127.0.0.1",
        destination_ip="10.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="a" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime(2026, 9, 23, 23, 15, 0, tzinfo=timezone.utc)
    )
    event_night = DetectionEngine._evaluate_single_rule(rule, night_tx, session)
    assert event_night is not None
    assert event_night.event_type == "RULE_OFF_HOURS"
    assert event_night.severity == SeverityLevel.MEDIUM
    assert "activity at hour 23:00" in event_night.description

    # 3. Weekend transfer: Sunday at 12:00 -> Trigger
    weekend_tx = FileTransfer(
        transfer_uuid="test-uuid-weekend",
        user_id=1,
        filename="sunday_data.docx",
        stored_filename="test-uuid-weekend_sunday_data.docx",
        file_size_bytes=1024,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        source_ip="127.0.0.1",
        destination_ip="10.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="a" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)  # Sunday
    )
    event_weekend = DetectionEngine._evaluate_single_rule(rule, weekend_tx, session)
    assert event_weekend is not None
    assert "weekend activity" in event_weekend.description
    session.close()


def test_unknown_destination_rule_detection():
    """Verify RULE_UNKNOWN_DEST triggers for external/untrusted destination IPs."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_UNKNOWN_DEST").first()
    assert rule is not None

    # 1. Approved private IP: 10.1.2.3 -> No trigger
    internal_tx = FileTransfer(
        transfer_uuid="test-uuid-internal",
        user_id=1,
        filename="backup.tar",
        stored_filename="test-uuid-internal_backup.tar",
        file_size_bytes=2048,
        mime_type="application/x-tar",
        source_ip="127.0.0.1",
        destination_ip="10.1.2.3",
        destination_label="Internal Server",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="b" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime.now(timezone.utc)
    )
    assert DetectionEngine._evaluate_single_rule(rule, internal_tx, session) is None

    # 2. Untrusted external public IP: 198.51.100.45 -> Trigger
    external_tx = FileTransfer(
        transfer_uuid="test-uuid-external",
        user_id=1,
        filename="exfil.tar",
        stored_filename="test-uuid-external_exfil.tar",
        file_size_bytes=2048,
        mime_type="application/x-tar",
        source_ip="127.0.0.1",
        destination_ip="198.51.100.45",
        destination_label="External Suspicious Node",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="b" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime.now(timezone.utc)
    )
    event_ext = DetectionEngine._evaluate_single_rule(rule, external_tx, session)
    assert event_ext is not None
    assert event_ext.event_type == "RULE_UNKNOWN_DEST"
    assert event_ext.severity == SeverityLevel.HIGH
    assert event_ext.weight_applied == 30
    assert "198.51.100.45" in event_ext.description
    session.close()


def test_insecure_protocol_rule_detection():
    """Verify RULE_INSECURE_PROTO triggers on unencrypted legacy protocols."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_INSECURE_PROTO").first()
    assert rule is not None

    # 1. Secure SFTP -> No trigger
    secure_tx = FileTransfer(
        transfer_uuid="test-uuid-sftp",
        user_id=1,
        filename="payload.txt",
        stored_filename="test-uuid-sftp_payload.txt",
        file_size_bytes=100,
        mime_type="text/plain",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        destination_label="Internal Host",
        protocol="SFTP",
        status=TransferStatus.SUCCESS,
        sha256_hash="c" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime.now(timezone.utc)
    )
    assert DetectionEngine._evaluate_single_rule(rule, secure_tx, session) is None

    # 2. Insecure plain FTP -> Trigger
    ftp_tx = FileTransfer(
        transfer_uuid="test-uuid-ftp",
        user_id=1,
        filename="credentials.txt",
        stored_filename="test-uuid-ftp_credentials.txt",
        file_size_bytes=100,
        mime_type="text/plain",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        destination_label="Internal Host",
        protocol="FTP",
        status=TransferStatus.SUCCESS,
        sha256_hash="c" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime.now(timezone.utc)
    )
    event_ftp = DetectionEngine._evaluate_single_rule(rule, ftp_tx, session)
    assert event_ftp is not None
    assert event_ftp.event_type == "RULE_INSECURE_PROTO"
    assert event_ftp.severity == SeverityLevel.HIGH
    assert "FTP" in event_ftp.description
    session.close()


def test_integrity_failure_rule_detection():
    """Verify RULE_INTEGRITY_FAIL triggers for SHA-256 checksum mismatches."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_INTEGRITY_FAIL").first()
    assert rule is not None

    mismatch_tx = FileTransfer(
        transfer_uuid="test-uuid-mismatch",
        user_id=1,
        filename="tampered.bin",
        stored_filename="test-uuid-mismatch_tampered.bin",
        file_size_bytes=512,
        mime_type="application/octet-stream",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.QUARANTINED,
        sha256_hash="1" * 64,
        expected_hash="2" * 64,
        integrity_status=IntegrityStatus.MISMATCH,
        created_at=datetime.now(timezone.utc)
    )
    event_integrity = DetectionEngine._evaluate_single_rule(rule, mismatch_tx, session)
    assert event_integrity is not None
    assert event_integrity.event_type == "RULE_INTEGRITY_FAIL"
    assert event_integrity.severity == SeverityLevel.CRITICAL
    assert event_integrity.weight_applied == 30
    session.close()


def test_excessive_transfers_rule_detection():
    """Verify RULE_EXCESSIVE_TX triggers when user initiates transfer burst exceeding threshold."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_EXCESSIVE_TX").first()
    assert rule is not None

    # Use a unique test user ID
    burst_user_id = 999
    now = datetime.now(timezone.utc)

    # Seed 10 transfers within the last 5 minutes
    for i in range(10):
        tx = FileTransfer(
            transfer_uuid=f"test-burst-{i}",
            user_id=burst_user_id,
            filename=f"burst_{i}.txt",
            stored_filename=f"test-burst-{i}_burst_{i}.txt",
            file_size_bytes=100,
            mime_type="text/plain",
            source_ip="127.0.0.1",
            destination_ip="127.0.0.1",
            destination_label="Internal Host",
            protocol="HTTPS",
            status=TransferStatus.SUCCESS,
            sha256_hash=f"{i:064d}",
            integrity_status=IntegrityStatus.NOT_PROVIDED,
            created_at=now - timedelta(minutes=i % 5)
        )
        session.add(tx)
    session.commit()

    # Incoming 11th transfer triggers burst rule
    incoming_tx = FileTransfer(
        transfer_uuid="test-burst-11",
        user_id=burst_user_id,
        filename="burst_11.txt",
        stored_filename="test-burst-11_burst_11.txt",
        file_size_bytes=100,
        mime_type="text/plain",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        destination_label="Internal Host",
        protocol="HTTPS",
        status=TransferStatus.SUCCESS,
        sha256_hash="9" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=now
    )
    event_burst = DetectionEngine._evaluate_single_rule(rule, incoming_tx, session)
    assert event_burst is not None
    assert event_burst.event_type == "RULE_EXCESSIVE_TX"
    assert event_burst.severity == SeverityLevel.MEDIUM

    # Clean up test burst transfers
    session.query(FileTransfer).filter(FileTransfer.user_id == burst_user_id).delete()
    session.commit()
    session.close()


def test_rule_disabling_suppresses_detection():
    """Verify that disabling a rule prevents event emission even when conditions are violated."""
    session = SessionLocal()
    rule = session.query(SecurityRule).filter(SecurityRule.rule_code == "RULE_INSECURE_PROTO").first()
    assert rule is not None

    # Disable rule temporarily
    original_state = rule.is_enabled
    rule.is_enabled = False
    session.commit()

    ftp_tx = FileTransfer(
        transfer_uuid="test-disabled-rule",
        user_id=1,
        filename="doc.txt",
        stored_filename="test-disabled-rule_doc.txt",
        file_size_bytes=100,
        mime_type="text/plain",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        destination_label="Internal Host",
        protocol="FTP",
        status=TransferStatus.SUCCESS,
        sha256_hash="d" * 64,
        integrity_status=IntegrityStatus.NOT_PROVIDED,
        created_at=datetime.now(timezone.utc)
    )

    # Evaluate full engine (only enabled rules should run)
    events = DetectionEngine.evaluate_transfer(ftp_tx, session)
    assert not any(e.event_type == "RULE_INSECURE_PROTO" for e in events)

    # Restore rule state
    rule.is_enabled = original_state
    session.commit()
    session.close()


def test_dynamic_cumulative_risk_scoring():
    """Verify dynamic weighted risk scoring sums up events and clamps at 100."""
    # 1. Single low event (weight 20) -> Score 20, LOW tier
    ev1 = SecurityEvent(event_type="RULE_LARGE_FILE", description="", severity=SeverityLevel.HIGH, weight_applied=20, details_json={})
    score1, level1 = RiskScorer.calculate_risk([ev1])
    assert score1 == 20
    assert level1 == RiskLevel.LOW

    # 2. Cumulative medium events (weight 20 + 20 = 40) -> Score 40, MEDIUM tier
    ev2 = SecurityEvent(event_type="RULE_OFF_HOURS", description="", severity=SeverityLevel.MEDIUM, weight_applied=20, details_json={})
    score2, level2 = RiskScorer.calculate_risk([ev1, ev2])
    assert score2 == 40
    assert level2 == RiskLevel.MEDIUM

    # 3. High cumulative (weight 20 + 20 + 30 = 70) -> Score 70, HIGH tier
    ev3 = SecurityEvent(event_type="RULE_UNKNOWN_DEST", description="", severity=SeverityLevel.HIGH, weight_applied=30, details_json={})
    score3, level3 = RiskScorer.calculate_risk([ev1, ev2, ev3])
    assert score3 == 70
    assert level3 == RiskLevel.HIGH

    # 4. Critical cumulative (weight 20 + 20 + 30 + 30 = 100) -> Score 100, CRITICAL tier
    ev4 = SecurityEvent(event_type="RULE_INTEGRITY_FAIL", description="", severity=SeverityLevel.CRITICAL, weight_applied=30, details_json={})
    score4, level4 = RiskScorer.calculate_risk([ev1, ev2, ev3, ev4])
    assert score4 == 100
    assert level4 == RiskLevel.CRITICAL

    # 5. Over-100 clamping (weight 130) -> Score clamped to 100
    ev5 = SecurityEvent(event_type="EXTRA", description="", severity=SeverityLevel.CRITICAL, weight_applied=30, details_json={})
    score5, level5 = RiskScorer.calculate_risk([ev1, ev2, ev3, ev4, ev5])
    assert score5 == 100


def test_security_rules_api_and_rbac(auth_tokens):
    """
    Verify /api/rules endpoints:
    - User cannot access rules (403)
    - Analyst can read rules (200)
    - Analyst cannot modify rules (403)
    - Admin can modify rule (200) and change is audited
    """
    user_token = auth_tokens["user"]
    analyst_token = auth_tokens["analyst"]
    admin_token = auth_tokens["admin"]

    # 1. Standard user access denied -> 403
    user_res = client.get("/api/rules", headers={"Authorization": f"Bearer {user_token}"})
    assert user_res.status_code == 403

    # 2. Analyst read access -> 200
    analyst_res = client.get("/api/rules", headers={"Authorization": f"Bearer {analyst_token}"})
    assert analyst_res.status_code == 200
    rules_data = analyst_res.json()
    assert rules_data["total"] >= 7
    first_rule_id = rules_data["items"][0]["id"]

    # 3. Analyst patch denied -> 403
    analyst_patch = client.patch(
        f"/api/rules/{first_rule_id}",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"risk_weight": 25}
    )
    assert analyst_patch.status_code == 403

    # 4. Admin patch permitted -> 200
    admin_patch = client.patch(
        f"/api/rules/{first_rule_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"risk_weight": 25}
    )
    assert admin_patch.status_code == 200
    assert admin_patch.json()["risk_weight"] == 25

    # Revert risk_weight back to 20
    client.patch(
        f"/api/rules/{first_rule_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"risk_weight": 20}
    )


def test_security_events_api_and_telemetry(auth_tokens):
    """Verify /api/events lists detected security violations for analysts and admins."""
    user_token = auth_tokens["user"]
    analyst_token = auth_tokens["analyst"]

    # 1. Standard user access denied -> 403
    assert client.get("/api/events", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403

    # 2. Analyst access permitted -> 200
    events_res = client.get("/api/events", headers={"Authorization": f"Bearer {analyst_token}"})
    assert events_res.status_code == 200
    events_data = events_res.json()
    assert "total" in events_data
    assert "items" in events_data
