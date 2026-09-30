from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.models import User, ThreatIntelRecord, ThreatLevel
from backend.schemas.threat_intel import (
    ThreatIntelOut,
    ThreatIntelListOut,
    ThreatIntelCheckRequest,
    ThreatIntelCheckResponse,
)
from backend.threat_intel.threat_service import ThreatIntelService
from backend.api.dependencies import require_analyst_or_admin

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("", response_model=ThreatIntelListOut)
def list_threat_records(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    threat_level: Optional[ThreatLevel] = None,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Lists cached IP reputation and threat intelligence records.
    Accessible to Analysts and Administrators.
    """
    query = db.query(ThreatIntelRecord)

    if threat_level:
        query = query.filter(ThreatIntelRecord.threat_level == threat_level)

    total = query.count()
    records = query.order_by(ThreatIntelRecord.last_checked_at.desc()).offset(skip).limit(limit).all()

    return ThreatIntelListOut(total=total, items=records)


@router.post("/lookup", response_model=ThreatIntelCheckResponse)
async def check_ip_reputation(
    payload: ThreatIntelCheckRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """
    Performs on-demand reputation lookup for a target IP address.
    Utilizes local cache, built-in threat signatures, and AbuseIPDB if configured.
    """
    record = await ThreatIntelService.check_ip(payload.ip_address, db)

    return ThreatIntelCheckResponse(
        ip_address=record.ip_address,
        reputation_score=record.reputation_score,
        threat_level=record.threat_level,
        threat_types=record.threat_types_json,
        source_provider=record.source_provider,
        is_cached=True,
        last_checked_at=record.last_checked_at
    )


@router.get("/{ip}", response_model=ThreatIntelOut)
def get_ip_reputation(
    ip: str,
    current_user: User = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db)
):
    """Retrieves cached threat intelligence details for an IP address."""
    record = db.query(ThreatIntelRecord).filter(ThreatIntelRecord.ip_address == ip.strip()).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No threat intelligence record found for {ip}. Use POST /lookup to query."
        )
    return record
