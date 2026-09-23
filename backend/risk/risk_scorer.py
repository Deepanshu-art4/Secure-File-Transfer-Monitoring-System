from typing import List, Tuple
from sqlalchemy.orm import Session

from backend.models import (
    FileTransfer,
    SecurityEvent,
    RiskLevel,
    SystemSetting,
    IntegrityStatus,
    TransferStatus
)
from backend.detection.rule_engine import DetectionEngine


class RiskScorer:
    """
    Weighted Dynamic Risk Scoring Engine (0 - 100 Scale).
    Aggregates rule violations, calculates normalized risk scores,
    classifies events into LOW, MEDIUM, HIGH, CRITICAL, and triggers automated mitigations.
    """

    @classmethod
    def calculate_risk(cls, events: List[SecurityEvent]) -> Tuple[int, RiskLevel]:
        """
        Calculates cumulative risk score and determines risk tier.
        0 - 29: LOW
        30 - 59: MEDIUM
        60 - 79: HIGH
        80 - 100: CRITICAL
        """
        raw_score = sum(event.weight_applied for event in events)
        clamped_score = min(100, max(0, raw_score))

        if clamped_score >= 80:
            level = RiskLevel.CRITICAL
        elif clamped_score >= 60:
            level = RiskLevel.HIGH
        elif clamped_score >= 30:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return clamped_score, level

    @classmethod
    def evaluate_and_update(
        cls,
        transfer: FileTransfer,
        db: Session
    ) -> Tuple[int, RiskLevel, List[SecurityEvent]]:
        """
        Evaluates transfer through DetectionEngine, creates SecurityEvent records,
        calculates cumulative risk, updates FileTransfer risk metrics, and triggers automated quarantine if critical.
        """
        # 1. Run detection rules
        events = DetectionEngine.evaluate_transfer(transfer, db)

        # 2. Persist triggered security events
        for event in events:
            db.add(event)

        # 3. Calculate dynamic risk score
        risk_score, risk_level = cls.calculate_risk(events)

        # Preserve higher existing risk score if transfer was already flagged
        if transfer.risk_score > risk_score:
            risk_score = transfer.risk_score
            risk_level = transfer.risk_level
        else:
            transfer.risk_score = risk_score
            transfer.risk_level = risk_level

        # 4. Automated quarantine on CRITICAL risk or integrity failure
        auto_quarantine_setting = db.query(SystemSetting).filter(
            SystemSetting.setting_key == "AUTOMATIC_QUARANTINE_ON_CRITICAL"
        ).first()
        auto_quarantine_enabled = True
        if auto_quarantine_setting and auto_quarantine_setting.setting_value.lower() == "false":
            auto_quarantine_enabled = False

        should_quarantine = (
            (risk_level == RiskLevel.CRITICAL and auto_quarantine_enabled) or
            (transfer.integrity_status == IntegrityStatus.MISMATCH)
        )

        if should_quarantine and not transfer.is_quarantined:
            from backend.services.transfer_service import TransferService
            TransferService.quarantine_file(
                transfer,
                db,
                reason=f"Automated quarantine: {risk_level.value} risk score ({risk_score}) detected"
            )

        db.commit()
        db.refresh(transfer)

        return risk_score, risk_level, events
