from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.core.config import settings
from backend.core.database import engine, Base
from backend.api.routes import auth_router, users_router, transfers_router


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
