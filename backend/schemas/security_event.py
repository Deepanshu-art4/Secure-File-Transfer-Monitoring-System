from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from backend.models.security_rule import SeverityLevel


class SecurityEventOut(BaseModel):
    id: int
    transfer_id: int
    rule_id: Optional[int] = None
    event_type: str
    description: str
    severity: SeverityLevel
    weight_applied: int
    details_json: Dict[str, Any]
    created_at: datetime

    model_config = {
        "from_attributes": True
    }


class SecurityEventListOut(BaseModel):
    total: int
    items: List[SecurityEventOut]
