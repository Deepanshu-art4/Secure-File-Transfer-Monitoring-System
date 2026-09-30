"""
Automated Test Suite for SOC Platform Capabilities:
- Incident & Alert Management lifecycle (OPEN -> INVESTIGATING -> RESOLVED)
- Modular Threat Intelligence and IP reputation
- Real-time SOC Monitoring KPIs & Statistics
- Tamper-evident Audit Trail search & filtering
- Compliance & Executive Reporting (PDF & CSV exports)
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.main import app
from backend.core.database import SessionLocal
from backend.models import (
    FileTransfer,
    Alert,
    AlertStatus,
    SeverityLevel,
    RiskLevel,
    TransferStatus,
    IntegrityStatus,
    AuditLog,
    ThreatIntelRecord,
    ThreatLevel,
)

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


def test_health_check():
    """Verify system health check endpoint returns 200 and correct status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert "timestamp" in data


def test_soc_monitoring_stats(auth_tokens):
    """Verify SOC dashboard metrics calculation and structure."""
    token = auth_tokens["analyst"]
    res = client.get("/api/monitoring/stats", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()

    assert "total_transfers" in data
    assert "quarantined_count" in data
    assert "avg_risk_score" in data
    assert "total_alerts" in data
    assert "severity_counts" in data
    assert "status_counts" in data
    assert "protocol_counts" in data
    assert "recent_transfers" in data
    assert isinstance(data["recent_transfers"], list)


def test_threat_intel_lookup_private_ip(auth_tokens):
    """Verify threat intelligence correctly identifies RFC 1918 internal/loopback IPs."""
    token = auth_tokens["analyst"]
    res = client.post(
        "/api/threat-intel/lookup",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_address": "192.168.1.50"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["ip_address"] == "192.168.1.50"
    assert data["threat_level"] == "CLEAN"
    assert data["reputation_score"] == 0
    assert "RFC 1918 Private / Loopback Network" in data["threat_types"]


def test_threat_intel_lookup_known_malicious_ip(auth_tokens):
    """Verify threat intelligence flags known threat signatures."""
    token = auth_tokens["analyst"]
    res = client.post(
        "/api/threat-intel/lookup",
        headers={"Authorization": f"Bearer {token}"},
        json={"ip_address": "185.220.101.5"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["ip_address"] == "185.220.101.5"
    assert data["threat_level"] == "MALICIOUS"
    assert data["reputation_score"] >= 80


def test_threat_intel_listing(auth_tokens):
    """Verify listing threat intelligence records with pagination."""
    token = auth_tokens["admin"]
    res = client.get("/api/threat-intel", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 1


def test_alert_lifecycle_and_triage(auth_tokens):
    """
    Test alert workflow:
    1. Seed an incident alert
    2. Retrieve alert details
    3. Update status to INVESTIGATING with notes and assignee
    4. Transition status to RESOLVED
    """
    db = SessionLocal()
    import uuid
    alert = Alert(
        alert_uuid=f"test-incident-{uuid.uuid4()}",
        title="Test Security Violation: Rapid Bursts",
        description="Automated test incident description",
        severity=SeverityLevel.HIGH,
        risk_score=75,
        status=AlertStatus.OPEN
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    alert_id = alert.id
    db.close()

    analyst_token = auth_tokens["analyst"]

    # 1. Fetch alert
    res = client.get(f"/api/alerts/{alert_id}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OPEN"
    assert data["severity"] == "HIGH"
    assert data["risk_score"] == 75

    # 2. Update to INVESTIGATING
    update_res = client.patch(
        f"/api/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "status": "INVESTIGATING",
            "assigned_to": 2,
            "analyst_notes": "Assigned to SOC Tier-2 analyst for deep payload packet inspection."
        }
    )
    assert update_res.status_code == 200
    updated_data = update_res.json()
    assert updated_data["status"] == "INVESTIGATING"
    assert updated_data["analyst_notes"] == "Assigned to SOC Tier-2 analyst for deep payload packet inspection."

    # 3. Transition to RESOLVED
    resolve_res = client.patch(
        f"/api/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "status": "RESOLVED",
            "analyst_notes": "Mitigated: IP temporarily banned at firewall."
        }
    )
    assert resolve_res.status_code == 200
    resolved_data = resolve_res.json()
    assert resolved_data["status"] == "RESOLVED"
    assert resolved_data["resolved_at"] is not None


def test_audit_logs_listing_and_filtering(auth_tokens):
    """Verify audit log endpoint with role-based filtering and action filtering."""
    analyst_token = auth_tokens["analyst"]
    res = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] > 0

    # Filter by specific action
    filter_res = client.get("/api/audit-logs?action=FILE_UPLOAD", headers={"Authorization": f"Bearer {analyst_token}"})
    assert filter_res.status_code == 200
    filter_data = filter_res.json()
    for item in filter_data["items"]:
        assert item["action"] == "FILE_UPLOAD"


def test_transfers_csv_report_export(auth_tokens):
    """Verify transfers CSV export returns valid CSV content."""
    admin_token = auth_tokens["admin"]
    res = client.get("/api/reports/transfers/csv", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
    assert "Transfer UUID,Filename,File Size (Bytes)" in res.text


def test_audit_logs_csv_report_export(auth_tokens):
    """Verify audit logs CSV export returns valid CSV content."""
    analyst_token = auth_tokens["analyst"]
    res = client.get("/api/reports/audit/csv", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
    assert "Log ID,Timestamp (UTC),Username,Action" in res.text


def test_transfers_pdf_report_export(auth_tokens):
    """Verify transfers PDF report generation returns valid PDF binary."""
    admin_token = auth_tokens["admin"]
    res = client.get("/api/reports/transfers/pdf", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert "application/pdf" in res.headers.get("content-type", "")
    # Check PDF magic bytes '%PDF'
    assert res.content.startswith(b"%PDF")


def test_alerts_pdf_report_export(auth_tokens):
    """Verify incidents PDF report generation returns valid PDF binary."""
    analyst_token = auth_tokens["analyst"]
    res = client.get("/api/reports/alerts/pdf", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200
    assert "application/pdf" in res.headers.get("content-type", "")
    assert res.content.startswith(b"%PDF")
