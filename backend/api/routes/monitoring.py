import json
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from backend.core.database import get_db, SessionLocal
from backend.models import User
from backend.api.dependencies import get_current_user
from backend.monitoring.stats_service import StatsService
from backend.monitoring.connection_manager import ws_manager
from backend.schemas.monitoring import SOCDashboardStatsOut

router = APIRouter(prefix="/monitoring", tags=["SOC Telemetry & Real-Time Monitoring"])


@router.get("/stats", response_model=SOCDashboardStatsOut)
def get_soc_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns real-time aggregated SOC telemetry metrics, risk score distributions,
    and alert severity breakdown.
    """
    return StatsService.get_soc_dashboard_stats(db)


@router.websocket("/ws")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for live SOC telemetry broadcast.
    Pushes real-time file transfer events, security violations, and incident alert lifecycle changes.
    """
    await ws_manager.connect(websocket)
    try:
        # Push immediate snapshot upon connection
        with SessionLocal() as db:
            current_stats = StatsService.get_soc_dashboard_stats(db)
        await websocket.send_text(json.dumps({
            "type": "INITIAL_SNAPSHOT",
            "data": current_stats
        }, default=str))

        while True:
            # Keep connection open and receive potential client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
