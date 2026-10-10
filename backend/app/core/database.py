"""
Database Session and Engine Management.
Uses SQLite for local zero-dependency operation, fully abstracting SQLAlchemy 2.0
so switching to PostgreSQL merely requires updating DATABASE_URL.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from typing import Generator
from app.core.config import settings

# For SQLite, check_same_thread=False allows FastAPI multi-threading
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    echo=settings.debug
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """Dependency for providing database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db() -> None:
    """Create all tables on application startup."""
    import app.models  # Ensure models are imported
    Base.metadata.create_all(bind=engine)
