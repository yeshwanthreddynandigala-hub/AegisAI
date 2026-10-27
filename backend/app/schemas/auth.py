"""
Pydantic Schemas for Authentication, Registration, and User Identity.
"""

from pydantic import BaseModel, Field, ConfigDict, field_serializer
from typing import Optional
from datetime import datetime, timezone
import re


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Alphanumeric username")
    email: str = Field(..., description="Valid corporate or user email address")
    password: str = Field(..., min_length=8, description="Strong password (minimum 8 characters)")
    full_name: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = Field("ANALYST", description="Requested role (ANALYST or ADMIN)")


class UserLogin(BaseModel):
    username: str = Field(..., description="Registered username or email")
    password: str = Field(..., description="Password")


class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime) -> str:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
