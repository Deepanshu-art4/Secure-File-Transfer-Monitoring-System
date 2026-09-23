from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User, SecurityRule, RuleType, AuditLog
from backend.schemas.security_rule import SecurityRuleOut, SecurityRuleListOut, SecurityRuleUpdate
from backend.api.dependencies import require_admin, require_analyst_or_admin, get_client_ip

router = APIRouter(prefix="/rules", tags=["Security Detection Rules"])


@router.get("", response_model=SecurityRuleListOut)
def list_security_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    rule_type: Optional[RuleType] = None,
    is_enabled: Optional[bool] = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Lists all configured security detection rules with pagination and filters.
    Accessible to Analysts and Administrators.
    """
    query = db.query(SecurityRule)

    if rule_type:
        query = query.filter(SecurityRule.rule_type == rule_type)

    if is_enabled is not None:
        query = query.filter(SecurityRule.is_enabled == is_enabled)

    total = query.count()
    rules = query.order_by(SecurityRule.id.asc()).offset(skip).limit(limit).all()

    return SecurityRuleListOut(total=total, items=rules)


@router.get("/{rule_id}", response_model=SecurityRuleOut)
def get_security_rule(
    rule_id: int,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Retrieves specific detection rule definition and condition configuration."""
    rule = db.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security rule with ID {rule_id} not found"
        )
    return rule


@router.patch("/{rule_id}", response_model=SecurityRuleOut)
def update_security_rule(
    rule_id: int,
    payload: SecurityRuleUpdate,
    request: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    [Admin Only] Modifies rule thresholds, risk weights, severity, or toggles rule active state.
    Generates an immutable audit trail entry.
    """
    rule = db.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security rule with ID {rule_id} not found"
        )

    updated_fields = {}
    if payload.name is not None:
        rule.name = payload.name
        updated_fields["name"] = payload.name
    if payload.description is not None:
        rule.description = payload.description
        updated_fields["description"] = payload.description
    if payload.condition_config is not None:
        rule.condition_config = payload.condition_config
        updated_fields["condition_config"] = payload.condition_config
    if payload.risk_weight is not None:
        rule.risk_weight = payload.risk_weight
        updated_fields["risk_weight"] = payload.risk_weight
    if payload.severity is not None:
        rule.severity = payload.severity
        updated_fields["severity"] = payload.severity.value
    if payload.is_enabled is not None:
        rule.is_enabled = payload.is_enabled
        updated_fields["is_enabled"] = payload.is_enabled

    audit = AuditLog(
        user_id=current_admin.id,
        username=current_admin.username,
        action="SECURITY_RULE_UPDATED",
        resource_type="SECURITY_RULE",
        resource_id=rule.rule_code,
        ip_address=get_client_ip(request),
        status="SUCCESS",
        details_json=updated_fields
    )
    db.add(audit)
    db.commit()
    db.refresh(rule)

    return rule
