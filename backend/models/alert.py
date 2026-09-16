import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.core.database import Base
from backend.models.security_rule import SeverityLevel


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_uuid: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False
    )
    transfer_id: Mapped[int | None] = mapped_column(ForeignKey("file_transfers.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, values_callable=lambda obj: [e.value for e in obj]),
        default=SeverityLevel.HIGH,
        nullable=False,
        index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, values_callable=lambda obj: [e.value for e in obj]),
        default=AlertStatus.OPEN,
        nullable=False,
        index=True
    )

    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    transfer = relationship("FileTransfer", back_populates="alerts")
    user = relationship("User", back_populates="alerts", foreign_keys=[user_id])
    assignee = relationship("User", back_populates="assigned_alerts", foreign_keys=[assigned_to])
    notifications = relationship("Notification", back_populates="alert", cascade="all, delete-orphan")
