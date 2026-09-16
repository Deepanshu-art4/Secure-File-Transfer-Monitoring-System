import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, Text, JSON, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.core.database import Base


class RuleType(str, enum.Enum):
    FILE_SIZE = "FILE_SIZE"
    OFF_HOURS = "OFF_HOURS"
    UNKNOWN_DESTINATION = "UNKNOWN_DESTINATION"
    EXCESSIVE_TRANSFERS = "EXCESSIVE_TRANSFERS"
    INSECURE_PROTOCOL = "INSECURE_PROTOCOL"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    FAILED_PATTERN = "FAILED_PATTERN"


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityRule(Base):
    __tablename__ = "security_rules"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    rule_code: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rule_type: Mapped[RuleType] = mapped_column(
        Enum(RuleType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True
    )
    condition_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    risk_weight: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        Enum(SeverityLevel, values_callable=lambda obj: [e.value for e in obj]),
        default=SeverityLevel.MEDIUM,
        nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    security_events = relationship("SecurityEvent", back_populates="rule")
