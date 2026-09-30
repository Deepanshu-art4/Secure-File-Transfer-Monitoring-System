from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from backend.models.alert import AlertStatus
from backend.models.security_rule import SeverityLevel


class AlertOut(BaseModel):
    id: int
    alert_uuid: str
    transfer_id: Optional[int] = None
    user_id: Optional[int] = None
    title: str
    description: str
    severity: SeverityLevel
    risk_score: int
    status: AlertStatus
    assigned_to: Optional[int] = None
    analyst_notes: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True
    }


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[int] = None
    analyst_notes: Optional[str] = None


class AlertListOut(BaseModel):
    total: int
    items: List[AlertOut]
