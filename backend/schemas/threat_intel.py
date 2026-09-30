from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from backend.models.threat_intel import ThreatLevel


class ThreatIntelOut(BaseModel):
    id: int
    ip_address: str
    reputation_score: int
    threat_level: ThreatLevel
    threat_types_json: List[str]
    source_provider: str
    raw_response_json: Dict[str, Any]
    last_checked_at: datetime

    model_config = {
        "from_attributes": True
    }


class ThreatIntelCheckRequest(BaseModel):
    ip_address: str


class ThreatIntelCheckResponse(BaseModel):
    ip_address: str
    reputation_score: int
    threat_level: ThreatLevel
    threat_types: List[str]
    source_provider: str
    is_cached: bool
    last_checked_at: datetime


class ThreatIntelListOut(BaseModel):
    total: int
    items: List[ThreatIntelOut]
