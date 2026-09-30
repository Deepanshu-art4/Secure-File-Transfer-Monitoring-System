from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    ip_address: str
    status: str
    details_json: Dict[str, Any]
    created_at: datetime

    model_config = {
        "from_attributes": True
    }


class AuditLogListOut(BaseModel):
    total: int
    items: List[AuditLogOut]
