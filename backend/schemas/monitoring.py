from typing import Dict, List, Any
from pydantic import BaseModel


class RecentTransferItem(BaseModel):
    id: int
    transfer_uuid: str
    filename: str
    file_size_bytes: int
    status: str
    protocol: str
    risk_score: int
    risk_level: str
    created_at: str


class SOCDashboardStatsOut(BaseModel):
    total_transfers: int
    quarantined_count: int
    avg_risk_score: float
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    severity_counts: Dict[str, int]
    status_counts: Dict[str, int]
    protocol_counts: Dict[str, int]
    recent_transfers: List[RecentTransferItem]
