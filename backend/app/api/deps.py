"""
FastAPI Dependencies for Authentication and Role-Based Access Control (RBAC).
Enforces HTTP 401 for unauthenticated calls and HTTP 403 for insufficient privileges.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional, List, Callable
import jwt

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import UserModel, UserRole

# OAuth2 password bearer with auto_error=False to allow clean 401 custom error responses
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> UserModel:
    """
    Validates JWT bearer token and resolves the authenticated UserModel.
    Returns HTTP 401 if token is missing, expired, or invalid.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload: missing subject.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account does not exist or was removed.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated."
        )

    return user


def require_roles(allowed_roles: List[str]) -> Callable:
    """
    Enforces that the authenticated user possesses one of the allowed roles.
    Returns HTTP 403 if privileges are insufficient.
    """
    def _role_checker(user: UserModel = Depends(get_current_user)) -> UserModel:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Operation requires one of the following roles: {', '.join(allowed_roles)}."
            )
        return user
    return _role_checker


# Role convenience dependencies
require_admin = require_roles([UserRole.ADMIN.value])
require_analyst = require_roles([UserRole.ANALYST.value, UserRole.ADMIN.value])
