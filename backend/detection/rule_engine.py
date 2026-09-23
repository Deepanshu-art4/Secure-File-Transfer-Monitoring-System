import ipaddress
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.models import (
    FileTransfer,
    SecurityRule,
    SecurityEvent,
    RuleType,
    IntegrityStatus,
    TransferStatus
)


class DetectionEngine:
    """
    Enterprise Cybersecurity Security Rule Detection Engine.
    Evaluates file transfer telemetry against all enabled security detection rules.
    """

    @classmethod
    def get_enabled_rules(cls, db: Session) -> List[SecurityRule]:
        """Fetches all currently active security rules from the database."""
        return db.query(SecurityRule).filter(SecurityRule.is_enabled == True).all()

    @classmethod
    def evaluate_transfer(cls, transfer: FileTransfer, db: Session) -> List[SecurityEvent]:
        """
        Executes real-time rule evaluation against a file transfer.
        Returns a list of generated SecurityEvent instances (not yet committed).
        """
        rules = cls.get_enabled_rules(db)
        triggered_events: List[SecurityEvent] = []

        for rule in rules:
            event = cls._evaluate_single_rule(rule, transfer, db)
            if event:
                triggered_events.append(event)

        return triggered_events

    @classmethod
    def _evaluate_single_rule(
        cls,
        rule: SecurityRule,
        transfer: FileTransfer,
        db: Session
    ) -> Optional[SecurityEvent]:
        """Dispatches transfer evaluation based on rule type."""
        config = rule.condition_config or {}

        if rule.rule_type == RuleType.FILE_SIZE:
            return cls._eval_file_size(rule, transfer, config)

        elif rule.rule_type == RuleType.OFF_HOURS:
            return cls._eval_off_hours(rule, transfer, config)

        elif rule.rule_type == RuleType.UNKNOWN_DESTINATION:
            return cls._eval_unknown_destination(rule, transfer, config)

        elif rule.rule_type == RuleType.EXCESSIVE_TRANSFERS:
            return cls._eval_excessive_transfers(rule, transfer, config, db)

        elif rule.rule_type == RuleType.INSECURE_PROTOCOL:
            return cls._eval_insecure_protocol(rule, transfer, config)

        elif rule.rule_type == RuleType.INTEGRITY_FAILURE:
            return cls._eval_integrity_failure(rule, transfer, config)

        elif rule.rule_type == RuleType.FAILED_PATTERN:
            return cls._eval_failed_pattern(rule, transfer, config, db)

        return None

    @classmethod
    def _eval_file_size(cls, rule: SecurityRule, transfer: FileTransfer, config: dict) -> Optional[SecurityEvent]:
        max_size_mb = config.get("max_size_mb", settings.RULE_LARGE_FILE_MB)
        threshold_bytes = max_size_mb * 1024 * 1024

        if transfer.file_size_bytes > threshold_bytes:
            actual_mb = round(transfer.file_size_bytes / (1024 * 1024), 2)
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"File transfer size ({actual_mb} MB) exceeded organizational threshold ({max_size_mb} MB)",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "file_size_bytes": transfer.file_size_bytes,
                    "file_size_mb": actual_mb,
                    "threshold_mb": max_size_mb,
                    "filename": transfer.filename
                }
            )
        return None

    @classmethod
    def _eval_off_hours(cls, rule: SecurityRule, transfer: FileTransfer, config: dict) -> Optional[SecurityEvent]:
        start_hour = config.get("work_start_hour", settings.RULE_WORK_HOURS_START)
        end_hour = config.get("work_end_hour", settings.RULE_WORK_HOURS_END)

        transfer_time = transfer.created_at or datetime.now(timezone.utc)
        # Check weekday: 5=Saturday, 6=Sunday
        is_weekend = transfer_time.weekday() >= 5
        is_outside_work_hours = (transfer_time.hour < start_hour or transfer_time.hour >= end_hour)

        if is_weekend or is_outside_work_hours:
            reason = "weekend activity" if is_weekend else f"activity at hour {transfer_time.hour:02d}:00 (work hours: {start_hour:02d}:00 - {end_hour:02d}:00)"
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"Off-hours transfer detected: {reason}",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "transfer_time": transfer_time.isoformat(),
                    "hour": transfer_time.hour,
                    "weekday": transfer_time.weekday(),
                    "work_start_hour": start_hour,
                    "work_end_hour": end_hour,
                    "is_weekend": is_weekend
                }
            )
        return None

    @classmethod
    def _eval_unknown_destination(cls, rule: SecurityRule, transfer: FileTransfer, config: dict) -> Optional[SecurityEvent]:
        approved_subnets = config.get("approved_subnets", [
            "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.1/32"
        ])

        try:
            dest_ip = ipaddress.ip_address(transfer.destination_ip)
        except ValueError:
            # Invalid IP string treated as untrusted external
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"Invalid destination IP format: {transfer.destination_ip}",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={"destination_ip": transfer.destination_ip, "reason": "malformed_ip"}
            )

        is_approved = False
        for subnet_str in approved_subnets:
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                if dest_ip in network:
                    is_approved = True
                    break
            except ValueError:
                continue

        if not is_approved:
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"Transfer directed to untrusted external destination IP: {transfer.destination_ip}",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "destination_ip": transfer.destination_ip,
                    "destination_label": transfer.destination_label,
                    "approved_subnets": approved_subnets
                }
            )
        return None

    @classmethod
    def _eval_excessive_transfers(cls, rule: SecurityRule, transfer: FileTransfer, config: dict, db: Session) -> Optional[SecurityEvent]:
        threshold_count = config.get("threshold_count", settings.RULE_EXCESSIVE_TRANSFERS_COUNT)
        window_minutes = config.get("window_minutes", settings.RULE_EXCESSIVE_WINDOW_MINUTES)

        current_time = transfer.created_at or datetime.now(timezone.utc)
        window_start = current_time - timedelta(minutes=window_minutes)

        # Count transfers within detection window for this user
        count = db.query(FileTransfer).filter(
            FileTransfer.user_id == transfer.user_id,
            FileTransfer.created_at >= window_start,
            FileTransfer.created_at <= current_time
        ).count()

        if count >= threshold_count:
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"Excessive transfer burst: {count} transfers initiated in {window_minutes} minutes (threshold: {threshold_count})",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "count": count,
                    "threshold_count": threshold_count,
                    "window_minutes": window_minutes,
                    "user_id": transfer.user_id
                }
            )
        return None

    @classmethod
    def _eval_insecure_protocol(cls, rule: SecurityRule, transfer: FileTransfer, config: dict) -> Optional[SecurityEvent]:
        blocked_protocols = [p.upper() for p in config.get("blocked_protocols", ["FTP", "HTTP", "TELNET", "TFTP"])]
        transfer_proto = (transfer.protocol or "").strip().upper()

        if transfer_proto in blocked_protocols:
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"Cleartext/insecure protocol utilized: {transfer.protocol}",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "protocol": transfer.protocol,
                    "blocked_protocols": blocked_protocols
                }
            )
        return None

    @classmethod
    def _eval_integrity_failure(cls, rule: SecurityRule, transfer: FileTransfer, config: dict) -> Optional[SecurityEvent]:
        if transfer.integrity_status == IntegrityStatus.MISMATCH:
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description="SHA-256 cryptographic checksum mismatch: potential payload tampering or file corruption detected",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "actual_sha256": transfer.sha256_hash,
                    "expected_sha256": transfer.expected_hash,
                    "integrity_status": transfer.integrity_status.value
                }
            )
        return None

    @classmethod
    def _eval_failed_pattern(cls, rule: SecurityRule, transfer: FileTransfer, config: dict, db: Session) -> Optional[SecurityEvent]:
        failure_threshold = config.get("failure_threshold", settings.RULE_FAILED_ATTEMPTS_THRESHOLD)
        window_minutes = config.get("window_minutes", 15)

        current_time = transfer.created_at or datetime.now(timezone.utc)
        window_start = current_time - timedelta(minutes=window_minutes)

        failed_count = db.query(FileTransfer).filter(
            FileTransfer.user_id == transfer.user_id,
            FileTransfer.status.in_([TransferStatus.FAILED, TransferStatus.QUARANTINED]),
            FileTransfer.created_at >= window_start,
            FileTransfer.created_at <= current_time
        ).count()

        if failed_count >= failure_threshold:
            return SecurityEvent(
                transfer_id=transfer.id,
                rule_id=rule.id,
                event_type=rule.rule_code,
                description=f"Repeated transfer anomaly pattern: {failed_count} failed/quarantined transfers in {window_minutes} minutes",
                severity=rule.severity,
                weight_applied=rule.risk_weight,
                details_json={
                    "failed_count": failed_count,
                    "failure_threshold": failure_threshold,
                    "window_minutes": window_minutes,
                    "user_id": transfer.user_id
                }
            )
        return None
