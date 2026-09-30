from typing import Dict, Any
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models import (
    FileTransfer,
    Alert,
    AlertStatus,
    TransferStatus,
    SeverityLevel,
    RiskLevel
)


class StatsService:
    """
    SOC Dashboard KPI & Telemetry Aggregation Service.
    Computes real-time metrics, risk score distributions, and transfer health.
    """

    @classmethod
    def get_soc_dashboard_stats(cls, db: Session) -> Dict[str, Any]:
        """Calculates comprehensive SOC platform KPIs."""
        total_transfers = db.query(FileTransfer).count()
        quarantined_count = db.query(FileTransfer).filter(FileTransfer.is_quarantined == True).count()

        avg_risk = db.query(func.avg(FileTransfer.risk_score)).scalar() or 0.0

        # Alert statistics
        total_alerts = db.query(Alert).count()
        open_alerts = db.query(Alert).filter(Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING])).count()
        critical_alerts = db.query(Alert).filter(Alert.severity == SeverityLevel.CRITICAL).count()

        # Severity breakdown
        severity_counts = {
            "LOW": db.query(Alert).filter(Alert.severity == SeverityLevel.LOW).count(),
            "MEDIUM": db.query(Alert).filter(Alert.severity == SeverityLevel.MEDIUM).count(),
            "HIGH": db.query(Alert).filter(Alert.severity == SeverityLevel.HIGH).count(),
            "CRITICAL": db.query(Alert).filter(Alert.severity == SeverityLevel.CRITICAL).count(),
        }

        # Status breakdown
        status_counts = {
            "SUCCESS": db.query(FileTransfer).filter(FileTransfer.status == TransferStatus.SUCCESS).count(),
            "QUARANTINED": db.query(FileTransfer).filter(FileTransfer.status == TransferStatus.QUARANTINED).count(),
            "FAILED": db.query(FileTransfer).filter(FileTransfer.status == TransferStatus.FAILED).count(),
            "FLAGGED": db.query(FileTransfer).filter(FileTransfer.status == TransferStatus.FLAGGED).count(),
        }

        # Protocol distribution
        protocol_rows = db.query(
            FileTransfer.protocol, func.count(FileTransfer.id)
        ).group_by(FileTransfer.protocol).all()
        protocol_counts = {proto: count for proto, count in protocol_rows}

        # Recent transfer stream
        recent_transfers = db.query(FileTransfer).order_by(
            FileTransfer.created_at.desc()
        ).limit(10).all()

        recent_items = [
            {
                "id": t.id,
                "transfer_uuid": t.transfer_uuid,
                "filename": t.filename,
                "file_size_bytes": t.file_size_bytes,
                "status": t.status.value,
                "protocol": t.protocol,
                "risk_score": t.risk_score,
                "risk_level": t.risk_level.value,
                "created_at": t.created_at.isoformat()
            }
            for t in recent_transfers
        ]

        return {
            "total_transfers": total_transfers,
            "quarantined_count": quarantined_count,
            "avg_risk_score": round(float(avg_risk), 1),
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "protocol_counts": protocol_counts,
            "recent_transfers": recent_items
        }
