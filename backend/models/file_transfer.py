import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.core.database import Base


class TransferStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    QUARANTINED = "QUARANTINED"
    FLAGGED = "FLAGGED"


class IntegrityStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    NOT_PROVIDED = "NOT_PROVIDED"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileTransfer(Base):
    __tablename__ = "file_transfers"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    transfer_uuid: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), default="application/octet-stream", nullable=False)

    source_ip: Mapped[str] = mapped_column(String(45), default="127.0.0.1", nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), default="127.0.0.1", nullable=False, index=True)
    destination_label: Mapped[str] = mapped_column(String(100), default="Internal Host", nullable=False)

    protocol: Mapped[str] = mapped_column(String(20), default="HTTPS", nullable=False, index=True)
    status: Mapped[TransferStatus] = mapped_column(
        Enum(TransferStatus, values_callable=lambda obj: [e.value for e in obj]),
        default=TransferStatus.SUCCESS,
        nullable=False,
        index=True
    )

    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expected_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    integrity_status: Mapped[IntegrityStatus] = mapped_column(
        Enum(IntegrityStatus, values_callable=lambda obj: [e.value for e in obj]),
        default=IntegrityStatus.NOT_PROVIDED,
        nullable=False
    )

    transfer_duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    risk_level: Mapped[RiskLevel] = mapped_column(
        Enum(RiskLevel, values_callable=lambda obj: [e.value for e in obj]),
        default=RiskLevel.LOW,
        nullable=False,
        index=True
    )
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    # Relationships
    user = relationship("User", back_populates="transfers")
    security_events = relationship("SecurityEvent", back_populates="transfer", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="transfer")
