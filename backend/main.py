from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from backend.core.config import settings
from backend.core.database import engine, Base
from backend.monitoring.connection_manager import ws_manager
from backend.monitoring.stats_service import StatsService
from backend.core.database import SessionLocal
import json

from backend.api.routes import (
    auth_router,
    users_router,
    transfers_router,
    rules_router,
    events_router,
    alerts_router,
    threat_intel_router,
    monitoring_router,
    audit_router,
    reports_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown events.
    Verifies storage directories and database connectivity upon launch.
    """
    settings.ensure_directories_exist()
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Cybersecurity SOC Platform for Monitoring, Analyzing, and Detecting Suspicious File Transfers.",
    version="1.0.0",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# Configure CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)
app.include_router(transfers_router, prefix=settings.API_V1_STR)
app.include_router(rules_router, prefix=settings.API_V1_STR)
app.include_router(events_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(threat_intel_router, prefix=settings.API_V1_STR)
app.include_router(monitoring_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)


@app.websocket("/ws/telemetry")
async def ws_telemetry_shortcut(websocket: WebSocket):
    """Convenience direct WebSocket endpoint for real-time SOC frontend clients."""
    await ws_manager.connect(websocket)
    try:
        with SessionLocal() as db:
            current_stats = StatsService.get_soc_dashboard_stats(db)
        await websocket.send_text(json.dumps({
            "type": "INITIAL_SNAPSHOT",
            "data": current_stats
        }, default=str))

        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG"}))
    except Exception:
        ws_manager.disconnect(websocket)


@app.get(f"{settings.API_V1_STR}/health", tags=["System Health"])
def health_check():
    """
    Liveness and health check endpoint for monitoring agents and container orchestrators.
    """
    return {
        "status": "HEALTHY",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Mount frontend single page application
from pathlib import Path
from fastapi.staticfiles import StaticFiles

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists() and (frontend_dir / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
