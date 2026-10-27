"""
Database Model for Security Analysts, Administrators, and System Users.
Stores authentication identity and role-based access control assignments.
Passwords are strictly stored as bcrypt hashes; never in plaintext.
"""

from sqlalchemy import Column, String, Boolean
from datetime import datetime, timezone
import uuid
import enum

from app.core.database import Base, UTCDateTime


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"


class UserModel(Base):
    __tablename__ = "users"

    user_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), default=UserRole.ANALYST.value, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
