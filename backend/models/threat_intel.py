import enum
from datetime import datetime, timezone
from sqlalchemy import String, Integer, JSON, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column
from backend.core.database import Base


class ThreatLevel(str, enum.Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class ThreatIntelRecord(Base):
    __tablename__ = "threat_intelligence"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    reputation_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    threat_level: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel, values_callable=lambda obj: [e.value for e in obj]),
        default=ThreatLevel.UNKNOWN,
        nullable=False,
        index=True
    )
    threat_types_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    source_provider: Mapped[str] = mapped_column(String(60), default="Local Threat Cache", nullable=False)
    raw_response_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    last_checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
