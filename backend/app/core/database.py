"""
Database Session and Engine Management.
Uses SQLite for local zero-dependency operation, fully abstracting SQLAlchemy 2.0
so switching to PostgreSQL merely requires updating DATABASE_URL.
"""

from sqlalchemy import create_engine, TypeDecorator, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from typing import Generator
from datetime import datetime, timezone
from app.core.config import settings

class UTCDateTime(TypeDecorator):
    """
    Ensures that datetimes stored and retrieved from SQLite or other dialects
    are always timezone-aware UTC datetime instances.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except Exception:
                    pass
            if isinstance(value, datetime):
                if value.tzinfo is None:
                    return value.replace(tzinfo=timezone.utc)
                return value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except Exception:
                    pass
            if isinstance(value, datetime):
                if value.tzinfo is None:
                    return value.replace(tzinfo=timezone.utc)
                return value.astimezone(timezone.utc)
        return value

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
    """Create all tables on application startup and seed default system accounts."""
    import app.models  # Ensure models are imported
    Base.metadata.create_all(bind=engine)


def ensure_default_users(db: Session) -> None:
    """Seeds default admin and analyst users for local evaluation if they do not exist."""
    from app.models.user import UserModel, UserRole
    from app.core.security import hash_password
    import uuid

    admin_user = db.query(UserModel).filter(UserModel.username == "admin").first()
    if not admin_user:
        admin_user = UserModel(
            user_id=str(uuid.uuid4()),
            username="admin",
            email="admin@aegisai.local",
            hashed_password=hash_password(settings.default_admin_password),
            full_name="Security Administrator",
            role=UserRole.ADMIN.value,
            is_active=True
        )
        db.add(admin_user)

    analyst_user = db.query(UserModel).filter(UserModel.username == "analyst").first()
    if not analyst_user:
        analyst_user = UserModel(
            user_id=str(uuid.uuid4()),
            username="analyst",
            email="analyst@aegisai.local",
            hashed_password=hash_password(settings.default_analyst_password),
            full_name="SOC Lead Analyst",
            role=UserRole.ANALYST.value,
            is_active=True
        )
        db.add(analyst_user)

    db.commit()
