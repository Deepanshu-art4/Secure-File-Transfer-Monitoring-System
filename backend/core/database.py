from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from backend.core.config import settings

# Configure connection engine based on database dialect
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,  # Set to True for verbose SQL query debugging
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """
    SQLAlchemy 2.0 Declarative Base class.
    All ORM models inherit from this base.
    """
    pass


def get_db() -> Generator:
    """
    FastAPI dependency that yields an isolated database session per request
    and guarantees proper session cleanup and closing.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
