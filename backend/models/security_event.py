from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, JSON, DateTime, ForeignKey, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.core.database import Base
from backend.models.security_rule import SeverityLevel


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    transfer_id: Mapped[int] = mapped_column(ForeignKey("file_transfers.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("security_rules.id", ondelete="SET NULL"), nullable=True, index=True)

    event_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, values_callable=lambda obj: [e.value for e in obj]),
        default=SeverityLevel.MEDIUM,
        nullable=False
    )
    weight_applied: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    # Relationships
    transfer = relationship("FileTransfer", back_populates="security_events")
    rule = relationship("SecurityRule", back_populates="security_events")
