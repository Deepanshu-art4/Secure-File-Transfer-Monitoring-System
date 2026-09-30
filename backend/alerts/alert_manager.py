import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.models import (
    FileTransfer,
    SecurityEvent,
    Alert,
    AlertStatus,
    SeverityLevel,
    SystemSetting,
    User,
    AuditLog,
    Notification
)


class AlertManager:
    """
    Enterprise Incident & Alert Lifecycle Manager.
    Handles automated alert generation from risk thresholds, state transitions,
    analyst assignment, and incident audit logging.
    """

    @classmethod
    def get_alert_threshold(cls, db: Session) -> int:
        """Retrieves dynamic alert risk threshold from system settings (default: 30)."""
        setting = db.query(SystemSetting).filter(
            SystemSetting.setting_key == "DEFAULT_ALERT_RISK_THRESHOLD"
        ).first()
        if setting and setting.setting_value.isdigit():
            return int(setting.setting_value)
        return 30

    @classmethod
    def trigger_alert_if_eligible(
        cls,
        transfer: FileTransfer,
        events: List[SecurityEvent],
        db: Session
    ) -> Optional[Alert]:
        """
        Evaluates whether a transfer warrants an automated security alert.
        Generates an incident record when risk score meets or exceeds organizational threshold.
        """
        threshold = cls.get_alert_threshold(db)
        if transfer.risk_score < threshold:
            return None

        # Check if an alert already exists for this transfer
        existing_alert = db.query(Alert).filter(Alert.transfer_id == transfer.id).first()
        if existing_alert:
            existing_alert.risk_score = transfer.risk_score
            return existing_alert

        # Determine overall alert severity from highest event severity
        severity_rank = {
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        highest_severity = SeverityLevel.MEDIUM
        if events:
            highest_severity = max(events, key=lambda e: severity_rank.get(e.severity, 0)).severity

        # Build descriptive title
        violation_types = [e.event_type for e in events]
        summary_types = ", ".join(violation_types[:3])
        if len(violation_types) > 3:
            summary_types += f" (+{len(violation_types) - 3} more)"

        title = f"Security Incident: {summary_types} (Risk: {transfer.risk_score})"
        descriptions = [f"- [{e.severity.value}] {e.description}" for e in events]
        full_description = f"Automated SOC alert generated for transfer '{transfer.filename}'.\n\nTriggered Security Violations:\n" + "\n".join(descriptions)

        alert = Alert(
            alert_uuid=str(uuid.uuid4()),
            transfer_id=transfer.id,
            user_id=transfer.user_id,
            title=title,
            description=full_description,
            severity=highest_severity,
            risk_score=transfer.risk_score,
            status=AlertStatus.OPEN
        )
        db.add(alert)
        db.flush()

        # Create system notification
        notification = Notification(
            user_id=transfer.user_id,
            alert_id=alert.id,
            title=f"Security Alert Triggered on Transfer {transfer.filename}",
            message=f"Risk Score: {transfer.risk_score} ({highest_severity.value})",
            is_read=False
        )
        db.add(notification)

        # Audit log entry
        audit = AuditLog(
            user_id=transfer.user_id,
            username=transfer.username,
            action="ALERT_GENERATED",
            resource_type="ALERT",
            resource_id=alert.alert_uuid,
            status="SUCCESS",
            details_json={
                "alert_id": alert.id,
                "title": alert.title,
                "severity": alert.severity.value,
                "risk_score": alert.risk_score,
                "transfer_id": transfer.id
            }
        )
        db.add(audit)
        db.commit()
        db.refresh(alert)

        # Broadcast incident alert to real-time SOC telemetry
        try:
            import asyncio
            from backend.monitoring.connection_manager import ws_manager
            payload = {
                "type": "ALERT_TRIGGERED",
                "data": {
                    "id": alert.id,
                    "alert_uuid": alert.alert_uuid,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "risk_score": alert.risk_score,
                    "status": alert.status.value,
                    "transfer_id": alert.transfer_id,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None
                }
            }
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(ws_manager.broadcast(payload))
            except RuntimeError:
                pass
        except Exception:
            pass

        return alert

    @classmethod
    def update_alert(
        cls,
        alert: Alert,
        new_status: Optional[AlertStatus],
        analyst: User,
        analyst_notes: Optional[str],
        assigned_to: Optional[int],
        db: Session
    ) -> Alert:
        """
        Updates alert lifecycle state (OPEN -> INVESTIGATING -> RESOLVED / FALSE_POSITIVE),
        records analyst investigative notes, and handles assignee reassignment.
        """
        changes = {}

        if new_status is not None and new_status != alert.status:
            changes["previous_status"] = alert.status.value
            changes["new_status"] = new_status.value
            alert.status = new_status
            if new_status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]:
                alert.resolved_at = datetime.now(timezone.utc)
            else:
                alert.resolved_at = None

        if assigned_to is not None:
            changes["assigned_to"] = assigned_to
            alert.assigned_to = assigned_to

        if analyst_notes is not None:
            alert.analyst_notes = analyst_notes
            changes["notes_updated"] = True

        audit = AuditLog(
            user_id=analyst.id,
            username=analyst.username,
            action="ALERT_UPDATED",
            resource_type="ALERT",
            resource_id=alert.alert_uuid,
            status="SUCCESS",
            details_json=changes
        )
        db.add(audit)
        db.commit()
        db.refresh(alert)

        # Broadcast incident state change to real-time SOC telemetry
        try:
            import asyncio
            from backend.monitoring.connection_manager import ws_manager
            payload = {
                "type": "ALERT_UPDATED",
                "data": {
                    "id": alert.id,
                    "alert_uuid": alert.alert_uuid,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "risk_score": alert.risk_score,
                    "status": alert.status.value,
                    "assigned_to": alert.assigned_to,
                    "analyst_notes": alert.analyst_notes,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None
                }
            }
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(ws_manager.broadcast(payload))
            except RuntimeError:
                pass
        except Exception:
            pass

        return alert
