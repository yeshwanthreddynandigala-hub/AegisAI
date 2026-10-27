"""
Security & Cryptographic Operations.
Provides secure password hashing via bcrypt and short-lived JWT token management via PyJWT.
Never stores plaintext credentials or hardcoded production secrets.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import uuid
import bcrypt
import jwt

from app.core.config import settings

def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with an individual cryptographic salt.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a bcrypt hash.
    Constant-time comparison protects against timing attacks.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Generates a cryptographically signed, short-lived JWT access token.
    Claims include subject, expiration, issuance time, and unique token ID.
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({
        "exp": expire,
        "iat": now_utc,
        "nbf": now_utc,
        "jti": str(uuid.uuid4())
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates JWT signature and expiration.
    Raises jwt.ExpiredSignatureError if expired, or jwt.InvalidTokenError if invalid.
    """
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm]
    )
