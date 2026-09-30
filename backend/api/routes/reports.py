from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User
from backend.services.report_service import ReportService
from backend.api.dependencies import require_analyst_or_admin

router = APIRouter(prefix="/reports", tags=["Compliance & Security Reporting"])


@router.get("/transfers/csv")
def download_transfers_csv(
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Generates and downloads file transfer history as an RFC 4180 CSV spreadsheet."""
    csv_data = ReportService.generate_transfers_csv(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=transfers_audit_report.csv"}
    )


@router.get("/transfers/pdf")
def download_transfers_pdf(
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Generates and downloads formal SOC Transfer Security Audit in PDF format."""
    pdf_bytes = ReportService.generate_transfers_pdf(db)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=transfers_audit_report.pdf"}
    )


@router.get("/alerts/pdf")
def download_alerts_pdf(
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Generates and downloads formal SOC Security Incident & Threat Triage PDF Report."""
    pdf_bytes = ReportService.generate_alerts_pdf(db)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=security_incidents_report.pdf"}
    )


@router.get("/audit/csv")
def download_audit_logs_csv(
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Generates and downloads immutable SOC administrative audit trail as CSV."""
    csv_data = ReportService.generate_audit_logs_csv(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_audit_logs.csv"}
    )
