"""
API Router: Authentication & User Identity Management.
Provides secure user registration, bcrypt credential verification, and JWT access token issuance.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta
import uuid

from app.core.database import get_db
from app.core.config import settings
from app.core.security import hash_password, verify_password, create_access_token
from app.models.user import UserModel, UserRole
from app.schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    """
    Registers a new system user with salted bcrypt password hashing.
    By default, public registration provisions ANALYST privileges.
    """
    username_clean = payload.username.strip().lower()
    email_clean = payload.email.strip().lower()

    if not username_clean or len(username_clean) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters long."
        )

    if "@" not in email_clean or "." not in email_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid email address is required."
        )

    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    # Check for existing username or email
    existing_user = db.query(UserModel).filter(
        (UserModel.username == username_clean) | (UserModel.email == email_clean)
    ).first()

    if existing_user:
        if existing_user.username == username_clean:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Username '{username_clean}' is already registered."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{email_clean}' is already registered."
            )

    # Determine assigned role (safeguard: default to ANALYST unless ADMIN explicitly selected and validated)
    assigned_role = UserRole.ANALYST.value
    if payload.role and payload.role.upper() == UserRole.ADMIN.value:
        # If no users exist in system yet, allow first user to be ADMIN
        total_users = db.query(UserModel).count()
        if total_users == 0:
            assigned_role = UserRole.ADMIN.value
        else:
            # For security, public registration cannot escalate itself to ADMIN
            assigned_role = UserRole.ANALYST.value

    new_user = UserModel(
        user_id=str(uuid.uuid4()),
        username=username_clean,
        email=email_clean,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name.strip() if payload.full_name else None,
        role=assigned_role,
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse.model_validate(new_user)


@router.post("/login", response_model=TokenResponse)
def login_for_access_token(payload: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates user credentials and issues a signed, short-lived JWT bearer token.
    """
    identifier_clean = payload.username.strip().lower()

    # Allow login by either username or email
    user = db.query(UserModel).filter(
        (UserModel.username == identifier_clean) | (UserModel.email == identifier_clean)
    ).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator."
        )

    token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={
            "sub": user.user_id,
            "username": user.username,
            "role": user.role
        },
        expires_delta=token_expires
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user)
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(user: UserModel = Depends(get_current_user)):
    """
    Returns the authenticated user's profile and active role privileges.
    """
    return UserResponse.model_validate(user)
