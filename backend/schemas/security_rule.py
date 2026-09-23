from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from backend.models.security_rule import RuleType, SeverityLevel


class SecurityRuleBase(BaseModel):
    rule_code: str
    name: str
    description: str
    rule_type: RuleType
    condition_config: Dict[str, Any] = Field(default_factory=dict)
    risk_weight: int = Field(default=20, ge=1, le=100)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    is_enabled: bool = True


class SecurityRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_config: Optional[Dict[str, Any]] = None
    risk_weight: Optional[int] = Field(None, ge=1, le=100)
    severity: Optional[SeverityLevel] = None
    is_enabled: Optional[bool] = None


class SecurityRuleOut(SecurityRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True
    }


class SecurityRuleListOut(BaseModel):
    total: int
    items: List[SecurityRuleOut]
