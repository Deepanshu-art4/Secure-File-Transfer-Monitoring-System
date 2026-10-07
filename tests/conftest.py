import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.core.database import Base, engine
from scripts.init_db import init_database


@pytest.fixture(scope="session", autouse=True)
def setup_database_for_tests():
    """Ensure all relational tables and default seed data exist for tests."""
    Base.metadata.create_all(bind=engine)
    init_database()
    yield
