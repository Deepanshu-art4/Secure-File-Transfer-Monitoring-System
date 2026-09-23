from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from backend.models.file_transfer import TransferStatus, IntegrityStatus, RiskLevel


class TransferOut(BaseModel):
    id: int
    transfer_uuid: str
    user_id: int
    username: Optional[str] = None
    filename: str
    file_size_bytes: int
    mime_type: str
    source_ip: str
    destination_ip: str
    destination_label: str
    protocol: str
    status: TransferStatus
    sha256_hash: str
    expected_hash: Optional[str] = None
    integrity_status: IntegrityStatus
    transfer_duration_ms: int
    risk_score: int
    risk_level: RiskLevel
    is_quarantined: bool
    created_at: datetime

    model_config = {
        "from_attributes": True
    }


class TransferDetailOut(TransferOut):
    stored_filename: str


class TransferListOut(BaseModel):
    total: int
    items: List[TransferOut]


class IntegrityVerificationRequest(BaseModel):
    transfer_id: Optional[int] = None
    expected_hash: str = Field(..., min_length=64, max_length=64, description="64-character SHA-256 hex digest")
    actual_hash: Optional[str] = Field(None, min_length=64, max_length=64, description="Optional actual SHA-256 digest if not using transfer_id")


class IntegrityVerificationResponse(BaseModel):
    is_valid: bool
    expected_hash: str
    actual_hash: str
    integrity_status: IntegrityStatus
    message: str
    transfer_id: Optional[int] = None

