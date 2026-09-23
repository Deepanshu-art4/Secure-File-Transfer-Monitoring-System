from backend.api.routes.auth import router as auth_router
from backend.api.routes.users import router as users_router
from backend.api.routes.transfers import router as transfers_router
from backend.api.routes.rules import router as rules_router
from backend.api.routes.events import router as events_router

__all__ = [
    "auth_router",
    "users_router",
    "transfers_router",
    "rules_router",
    "events_router",
]


