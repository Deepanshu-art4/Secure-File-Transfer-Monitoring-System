from backend.api.routes.auth import router as auth_router
from backend.api.routes.users import router as users_router
from backend.api.routes.transfers import router as transfers_router
from backend.api.routes.rules import router as rules_router
from backend.api.routes.events import router as events_router
from backend.api.routes.alerts import router as alerts_router
from backend.api.routes.threat_intel import router as threat_intel_router
from backend.api.routes.monitoring import router as monitoring_router
from backend.api.routes.audit import router as audit_router
from backend.api.routes.reports import router as reports_router

__all__ = [
    "auth_router",
    "users_router",
    "transfers_router",
    "rules_router",
    "events_router",
    "alerts_router",
    "threat_intel_router",
    "monitoring_router",
    "audit_router",
    "reports_router",
]
