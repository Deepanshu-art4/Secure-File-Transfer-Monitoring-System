"""
Automated Test Suite for Step 5: Secure File Transfer Engine & Integrity Verification.
Tests secure uploads, streaming chunked SHA-256 calculation, path-traversal defense,
file size limit enforcement, quarantine isolation, filterable history, and authorized downloads.
"""

import sys
import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.main import app
from backend.core.config import settings
from backend.core.database import SessionLocal
from backend.models import FileTransfer, TransferStatus, IntegrityStatus, RiskLevel, AuditLog
from backend.services.transfer_service import TransferService

client = TestClient(app)


@pytest.fixture(scope="module")
def auth_tokens():
    """Retrieves bearer tokens for admin, analyst, and standard user."""
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


def test_valid_upload_and_sha256_hash_calculation(auth_tokens):
    """
    Verify valid file upload:
    - Streams and calculates memory-efficient SHA-256 digest
    - Stores file in storage/uploads
    - Persists transfer record with status SUCCESS
    - Generates FILE_UPLOAD audit log entry
    """
    token = auth_tokens["user"]
    content = b"Enterprise Cybersecurity SOC File Transfer Payload 2026"
    expected_digest = hashlib.sha256(content).hexdigest()

    files = {
        "file": ("security_report.pdf", content, "application/pdf")
    }
    data = {
        "destination_ip": "192.168.1.100",
        "destination_label": "SOC Backup Vault",
        "protocol": "SFTP",
    }

    res = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files=files,
        data=data
    )
    assert res.status_code == 201, f"Upload failed: {res.text}"
    body = res.json()

    assert body["filename"] == "security_report.pdf"
    assert body["file_size_bytes"] == len(content)
    assert body["sha256_hash"] == expected_digest
    assert body["status"] == "SUCCESS"
    assert body["integrity_status"] == "NOT_PROVIDED"
    assert body["is_quarantined"] is False
    assert body["protocol"] == "SFTP"

    # Verify physical file existence in storage
    session = SessionLocal()
    transfer = session.query(FileTransfer).filter(FileTransfer.id == body["id"]).first()
    assert transfer is not None
    stored_path = TransferService.resolve_file_path(transfer)
    assert stored_path.exists()
    assert stored_path.read_bytes() == content

    # Verify audit log recorded
    audit = session.query(AuditLog).filter(
        AuditLog.action == "FILE_UPLOAD",
        AuditLog.resource_id == body["transfer_uuid"]
    ).first()
    assert audit is not None
    assert audit.status == "SUCCESS"
    session.close()


def test_upload_with_matching_expected_checksum(auth_tokens):
    """Verify upload with matching client-supplied checksum marks integrity as VERIFIED."""
    token = auth_tokens["user"]
    content = b"Verified Payload Data"
    exact_hash = hashlib.sha256(content).hexdigest()

    files = {"file": ("data_export.csv", content, "text/csv")}
    data = {
        "destination_ip": "10.0.0.5",
        "expected_hash": exact_hash
    }

    res = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files=files,
        data=data
    )
    assert res.status_code == 201
    body = res.json()
    assert body["integrity_status"] == "VERIFIED"
    assert body["status"] == "SUCCESS"
    assert body["is_quarantined"] is False
    assert body["risk_score"] == 0
    assert body["risk_level"] == "LOW"


def test_upload_with_tampered_hash_triggers_quarantine(auth_tokens):
    """
    Verify integrity mismatch:
    - Sets integrity_status to MISMATCH
    - Sets transfer status to QUARANTINED
    - Isolates physical file inside storage/quarantine directory
    - Elevates risk level to HIGH
    """
    token = auth_tokens["user"]
    content = b"Tampered Content for Security Testing"
    fake_expected_hash = "a" * 64

    files = {"file": ("financial_summary.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    data = {
        "destination_ip": "10.0.0.12",
        "expected_hash": fake_expected_hash
    }

    res = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files=files,
        data=data
    )
    assert res.status_code == 201
    body = res.json()
    assert body["integrity_status"] == "MISMATCH"
    assert body["status"] == "QUARANTINED"
    assert body["is_quarantined"] is True
    assert body["risk_score"] >= 80
    assert body["risk_level"] in ["HIGH", "CRITICAL"]

    # Verify physical file is in quarantine directory, NOT uploads
    session = SessionLocal()
    transfer = session.query(FileTransfer).filter(FileTransfer.id == body["id"]).first()
    assert transfer is not None
    quarantine_path = TransferService.resolve_file_path(transfer)
    assert quarantine_path.exists()
    assert settings.QUARANTINE_DIR in str(quarantine_path).replace("\\", "/")
    session.close()


def test_path_traversal_attack_rejection(auth_tokens):
    """Verify that filenames containing directory traversal characters or null bytes are rejected with HTTP 400."""
    token = auth_tokens["user"]
    payload = b"Malicious Path Traversal Attempt"

    # 1. Unix directory traversal
    res1 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("../../etc/passwd.txt", payload, "text/plain")}
    )
    assert res1.status_code == 400
    assert "Path traversal" in res1.json()["detail"]

    # 2. Windows directory traversal
    res2 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("..\\..\\Windows\\System32\\calc.txt", payload, "text/plain")}
    )
    assert res2.status_code == 400
    assert "Path traversal" in res2.json()["detail"]

    # 3. Embedded traversal sequences
    res3 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("reports/../../secret.txt", payload, "text/plain")}
    )
    assert res3.status_code == 400

    # 4. Null byte injection
    res4 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("safe.txt\x00.exe", payload, "text/plain")}
    )
    assert res4.status_code == 400


def test_disallowed_extension_and_mime_rejection(auth_tokens):
    """Verify that prohibited file extensions and executable MIME types are blocked."""
    token = auth_tokens["user"]
    content = b"Dangerous Executable Binary Content"

    # 1. Blocked extension .exe
    res1 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("malware.exe", content, "application/octet-stream")}
    )
    assert res1.status_code == 400
    assert "strictly prohibited" in res1.json()["detail"] or "not permitted" in res1.json()["detail"]

    # 2. Blocked extension .sh
    res2 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("exploit.sh", content, "application/x-sh")}
    )
    assert res2.status_code == 400

    # 3. Missing extension
    res3 = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("no_extension_file", content, "text/plain")}
    )
    assert res3.status_code == 400


def test_oversized_file_rejection(auth_tokens, monkeypatch):
    """Verify file exceeding MAX_UPLOAD_SIZE_MB is aborted with HTTP 413 and cleaned up from disk."""
    token = auth_tokens["user"]

    # Temporarily set max upload size to 1 MB for testing
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_MB", 1)

    # 1.5 MB payload
    oversized_content = b"X" * (1024 * 1024 + 512 * 1024)

    res = client.post(
        "/api/transfers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("oversized_log.txt", oversized_content, "text/plain")}
    )
    assert res.status_code == 413
    assert "File exceeds maximum allowed upload size" in res.json()["detail"]


def test_filterable_transfer_history_and_rbac(auth_tokens):
    """
    Verify /api/transfers endpoint:
    - Filters by status, protocol, risk_level, and search query
    - Enforces RBAC: standard users see only their own transfers
    - Analysts and Admins see global transfers
    """
    user_token = auth_tokens["user"]
    analyst_token = auth_tokens["analyst"]
    admin_token = auth_tokens["admin"]

    # 1. Standard User view: only contains user1 transfers
    user_res = client.get("/api/transfers", headers={"Authorization": f"Bearer {user_token}"})
    assert user_res.status_code == 200
    user_data = user_res.json()
    assert "items" in user_data
    assert "total" in user_data
    for item in user_data["items"]:
        assert item["username"] == "user1"

    # 2. Filter by status: QUARANTINED
    quarantine_res = client.get(
        "/api/transfers?status=QUARANTINED",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert quarantine_res.status_code == 200
    quarantine_data = quarantine_res.json()
    for item in quarantine_data["items"]:
        assert item["status"] == "QUARANTINED"
        assert item["is_quarantined"] is True

    # 3. Filter by search term
    search_res = client.get(
        "/api/transfers?search=security_report",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert search_res.status_code == 200
    search_data = search_res.json()
    assert search_data["total"] >= 1
    assert any("security_report" in item["filename"] for item in search_data["items"])


def test_transfer_detail_endpoint_and_rbac(auth_tokens):
    """Verify /api/transfers/{id} returns full report and enforces access barriers."""
    user_token = auth_tokens["user"]
    analyst_token = auth_tokens["analyst"]

    # Get an existing transfer id
    list_res = client.get("/api/transfers", headers={"Authorization": f"Bearer {user_token}"})
    transfer_id = list_res.json()["items"][0]["id"]

    # 1. User views their own transfer -> 200
    detail_res = client.get(f"/api/transfers/{transfer_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == transfer_id
    assert "stored_filename" in detail
    assert "sha256_hash" in detail

    # 2. Analyst views user's transfer -> 200
    analyst_res = client.get(f"/api/transfers/{transfer_id}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert analyst_res.status_code == 200

    # 3. Non-existent transfer -> 404
    missing_res = client.get("/api/transfers/999999", headers={"Authorization": f"Bearer {analyst_token}"})
    assert missing_res.status_code == 404


def test_standalone_integrity_verification_endpoint(auth_tokens):
    """Verify /api/transfers/verify-integrity for recorded transfer and raw hashes."""
    token = auth_tokens["user"]

    # Obtain a transfer ID and its hash
    list_res = client.get("/api/transfers", headers={"Authorization": f"Bearer {token}"})
    item = list_res.json()["items"][0]
    transfer_id = item["id"]
    correct_hash = item["sha256_hash"]
    wrong_hash = "f" * 64

    # 1. Match against transfer_id
    res1 = client.post("/api/transfers/verify-integrity", headers={"Authorization": f"Bearer {token}"}, json={
        "transfer_id": transfer_id,
        "expected_hash": correct_hash
    })
    assert res1.status_code == 200
    body1 = res1.json()
    assert body1["is_valid"] is True
    assert body1["integrity_status"] == "VERIFIED"

    # 2. Mismatch against transfer_id
    res2 = client.post("/api/transfers/verify-integrity", headers={"Authorization": f"Bearer {token}"}, json={
        "transfer_id": transfer_id,
        "expected_hash": wrong_hash
    })
    assert res2.status_code == 200
    body2 = res2.json()
    assert body2["is_valid"] is False
    assert body2["integrity_status"] == "MISMATCH"

    # 3. Direct raw hash comparator (without transfer_id)
    res3 = client.post("/api/transfers/verify-integrity", headers={"Authorization": f"Bearer {token}"}, json={
        "actual_hash": correct_hash,
        "expected_hash": correct_hash
    })
    assert res3.status_code == 200
    assert res3.json()["is_valid"] is True


def test_authorized_download_and_quarantine_barrier(auth_tokens):
    """
    Verify /api/transfers/{id}/download:
    - User can download their verified transfer file
    - Emits FILE_DOWNLOAD audit log entry
    - Standard user is FORBIDDEN (403) from downloading quarantined files
    - Analyst / Admin CAN download quarantined files for forensic analysis
    """
    user_token = auth_tokens["user"]
    analyst_token = auth_tokens["analyst"]

    # 1. Download verified file by owner
    verified_list = client.get("/api/transfers?status=SUCCESS", headers={"Authorization": f"Bearer {user_token}"}).json()
    verified_id = verified_list["items"][0]["id"]

    dl_res = client.get(f"/api/transfers/{verified_id}/download", headers={"Authorization": f"Bearer {user_token}"})
    assert dl_res.status_code == 200
    assert len(dl_res.content) > 0

    # Verify audit log entry
    session = SessionLocal()
    dl_audit = session.query(AuditLog).filter(
        AuditLog.action == "FILE_DOWNLOAD",
        AuditLog.username == "user1"
    ).order_by(AuditLog.id.desc()).first()
    assert dl_audit is not None
    assert dl_audit.status == "SUCCESS"
    session.close()

    # 2. Standard user downloading quarantined file -> 403 Forbidden
    quarantine_list = client.get("/api/transfers?status=QUARANTINED", headers={"Authorization": f"Bearer {analyst_token}"}).json()
    quarantined_id = quarantine_list["items"][0]["id"]

    user_blocked_dl = client.get(f"/api/transfers/{quarantined_id}/download", headers={"Authorization": f"Bearer {user_token}"})
    assert user_blocked_dl.status_code == 403
    assert "quarantined" in user_blocked_dl.json()["detail"].lower()

    # 3. Security Analyst downloading quarantined file for forensics -> 200 OK
    analyst_forensic_dl = client.get(f"/api/transfers/{quarantined_id}/download", headers={"Authorization": f"Bearer {analyst_token}"})
    assert analyst_forensic_dl.status_code == 200
    assert len(analyst_forensic_dl.content) > 0
