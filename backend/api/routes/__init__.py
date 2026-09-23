from backend.api.routes.auth import router as auth_router
from backend.api.routes.users import router as users_router
from backend.api.routes.transfers import router as transfers_router

__all__ = [
    "auth_router",
    "users_router",
    "transfers_router",
]

