"""
Unit and Integration Tests for Authentication and Role-Based Access Control (RBAC).
Verifies:
1. Secure password hashing with bcrypt (no plaintext storage).
2. JWT access token generation, signature validation, and expiration enforcement.
3. User registration with validation and duplicate prevention.
4. Login with valid, invalid, and nonexistent credentials.
5. HTTP 401 for unauthenticated requests, missing tokens, invalid tokens, and expired tokens.
6. HTTP 403 for unauthorized role operations (Analyst vs Admin privileges).
7. Server-side role protection on sensitive endpoints (/agents, /evaluation/run-benchmark, /incidents/contain).
"""

import pytest
import uuid
from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db, ensure_default_users
from app.core.security import create_access_token, verify_password
from app.models.user import UserModel, UserRole
from app.models.incident import IncidentModel
from app.models.event import SecurityEventModel
from app.evaluation.benchmark_runner import _ensure_benchmark_agents


@pytest.fixture
def auth_client():
    """Provides isolated TestClient and database with default admin & analyst users."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestingSession()

    ensure_default_users(db)
    _ensure_benchmark_agents(db)

    def _override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
        yield c, db

    app.dependency_overrides.clear()
    db.close()


def test_password_hashing_never_stores_plaintext(auth_client):
    """Verifies that default and newly created users strictly store bcrypt hashes."""
    _, db = auth_client
    admin = db.query(UserModel).filter(UserModel.username == "admin").first()
    assert admin is not None
    assert admin.hashed_password != "AdminAegis2026!"
    assert admin.hashed_password.startswith("$2b$") or admin.hashed_password.startswith("$2a$")
    assert verify_password("AdminAegis2026!", admin.hashed_password) is True
    assert verify_password("WrongPassword!", admin.hashed_password) is False


def test_user_registration_success(auth_client):
    """POST /api/v1/auth/register registers new user with ANALYST role by default."""
    client, db = auth_client
    payload = {
        "username": "new_analyst_01",
        "email": "new_analyst@aegisai.local",
        "password": "SecurePassword123!",
        "full_name": "New SOC Analyst",
        "role": "ANALYST"
    }
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "new_analyst_01"
    assert data["email"] == "new_analyst@aegisai.local"
    assert data["role"] == "ANALYST"
    assert "password" not in data
    assert "hashed_password" not in data

    # Verify user exists in DB with hashed password
    user_in_db = db.query(UserModel).filter(UserModel.username == "new_analyst_01").first()
    assert user_in_db is not None
    assert user_in_db.hashed_password != "SecurePassword123!"
    assert verify_password("SecurePassword123!", user_in_db.hashed_password) is True


def test_user_registration_duplicate_username_and_email(auth_client):
    """Duplicate username or email registration returns HTTP 400."""
    client, _ = auth_client
    # Duplicate username
    resp_dup_user = client.post("/api/v1/auth/register", json={
        "username": "admin",
        "email": "unique_email@aegisai.local",
        "password": "ValidPassword123!"
    })
    assert resp_dup_user.status_code == 400
    assert "already registered" in resp_dup_user.json()["detail"]

    # Duplicate email
    resp_dup_email = client.post("/api/v1/auth/register", json={
        "username": "unique_user",
        "email": "admin@aegisai.local",
        "password": "ValidPassword123!"
    })
    assert resp_dup_email.status_code == 400
    assert "already registered" in resp_dup_email.json()["detail"]


def test_user_registration_validation(auth_client):
    """Invalid input (short password, invalid email) returns HTTP 400."""
    client, _ = auth_client
    # Password too short
    resp_short = client.post("/api/v1/auth/register", json={
        "username": "valid_user",
        "email": "user@example.com",
        "password": "123"
    })
    assert resp_short.status_code in [400, 422]

    # Invalid email
    resp_email = client.post("/api/v1/auth/register", json={
        "username": "valid_user_2",
        "email": "not_an_email",
        "password": "ValidPassword123!"
    })
    assert resp_email.status_code == 400


def test_login_valid_credentials(auth_client):
    """POST /api/v1/auth/login returns JWT bearer token and user metadata."""
    client, _ = auth_client
    resp = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "AdminAegis2026!"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "ADMIN"


def test_login_invalid_password(auth_client):
    """POST /api/v1/auth/login with wrong password returns HTTP 401."""
    client, _ = auth_client
    resp = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "IncorrectPassword!"
    })
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]


def test_login_nonexistent_user(auth_client):
    """POST /api/v1/auth/login with unknown username returns HTTP 401."""
    client, _ = auth_client
    resp = client.post("/api/v1/auth/login", json={
        "username": "ghost_user_999",
        "password": "AnyPassword123!"
    })
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]


def test_protected_endpoint_missing_token(auth_client):
    """Unauthenticated calls to protected routes return HTTP 401."""
    client, _ = auth_client
    # Overview
    r1 = client.get("/api/v1/overview/stats")
    assert r1.status_code == 401

    # Events
    r2 = client.get("/api/v1/events")
    assert r2.status_code == 401

    # Incidents
    r3 = client.get("/api/v1/incidents")
    assert r3.status_code == 401

    # Agents
    r4 = client.get("/api/v1/agents")
    assert r4.status_code == 401


def test_protected_endpoint_invalid_token(auth_client):
    """Calls with a tampered or invalid bearer token return HTTP 401."""
    client, _ = auth_client
    headers = {"Authorization": "Bearer invalid.token.garbage123"}
    resp = client.get("/api/v1/overview/stats", headers=headers)
    assert resp.status_code == 401
    assert "Invalid authentication token" in resp.json()["detail"]


def test_protected_endpoint_expired_token(auth_client):
    """Calls with an expired JWT access token return HTTP 401."""
    client, db = auth_client
    admin = db.query(UserModel).filter(UserModel.username == "admin").first()

    # Generate token already expired 10 minutes ago
    expired_token = create_access_token(
        data={"sub": admin.user_id, "username": admin.username, "role": admin.role},
        expires_delta=timedelta(minutes=-10)
    )

    headers = {"Authorization": f"Bearer {expired_token}"}
    resp = client.get("/api/v1/overview/stats", headers=headers)
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_role_rbac_analyst_cannot_create_agent(auth_client):
    """Analyst role attempting ADMIN-only agent creation returns HTTP 403 Forbidden."""
    client, db = auth_client
    analyst = db.query(UserModel).filter(UserModel.username == "analyst").first()
    analyst_token = create_access_token(data={"sub": analyst.user_id, "username": analyst.username, "role": analyst.role})

    headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "agent_id": "agent_unauthorized_probe",
        "name": "Probe Agent",
        "role": "Tester",
        "authorized_objective": "Test RBAC",
        "policy": {
            "version": "1.0",
            "allowed_tools": ["calculator"]
        }
    }
    resp = client.post("/api/v1/agents", json=payload, headers=headers)
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]


def test_role_rbac_admin_can_create_agent(auth_client):
    """Admin role attempting agent creation succeeds with HTTP 200."""
    client, db = auth_client
    admin = db.query(UserModel).filter(UserModel.username == "admin").first()
    admin_token = create_access_token(data={"sub": admin.user_id, "username": admin.username, "role": admin.role})

    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "agent_id": "agent_admin_provisioned_01",
        "name": "Admin Provisioned Agent",
        "role": "Security QA",
        "authorized_objective": "Authorized Admin Task",
        "policy": {
            "version": "1.0",
            "allowed_tools": ["calculator"]
        }
    }
    resp = client.post("/api/v1/agents", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "agent_admin_provisioned_01"


def test_role_rbac_analyst_cannot_run_benchmark(auth_client):
    """Analyst attempting POST /api/v1/evaluation/run-benchmark returns HTTP 403."""
    client, db = auth_client
    analyst = db.query(UserModel).filter(UserModel.username == "analyst").first()
    analyst_token = create_access_token(data={"sub": analyst.user_id, "username": analyst.username, "role": analyst.role})

    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.post("/api/v1/evaluation/run-benchmark", headers=headers)
    assert resp.status_code == 403
    assert "Forbidden" in resp.json()["detail"]


def test_role_rbac_analyst_cannot_contain_incident_admin_can(auth_client):
    """Analyst cannot contain incidents (HTTP 403); Admin can contain incidents (HTTP 200)."""
    client, db = auth_client

    # Create dummy incident
    inc = IncidentModel(
        incident_id="inc_rbac_test_001",
        session_id="sess_rbac_001",
        agent_id="agent_researcher_001",
        title="RBAC Test Incident",
        severity="HIGH",
        status="OPEN",
        primary_threat_category="CREDENTIAL_THEFT",
        summary="Test incident for containment RBAC",
        triggering_event_id="evt_001"
    )
    db.add(inc)
    db.commit()

    analyst = db.query(UserModel).filter(UserModel.username == "analyst").first()
    analyst_token = create_access_token(data={"sub": analyst.user_id, "username": analyst.username, "role": analyst.role})

    admin = db.query(UserModel).filter(UserModel.username == "admin").first()
    admin_token = create_access_token(data={"sub": admin.user_id, "username": admin.username, "role": admin.role})

    # 1. Analyst attempt -> 403
    resp_analyst = client.post("/api/v1/incidents/inc_rbac_test_001/contain", headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp_analyst.status_code == 403

    # 2. Admin attempt -> 200
    resp_admin = client.post("/api/v1/incidents/inc_rbac_test_001/contain", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp_admin.status_code == 200
    assert resp_admin.json()["status"] == "success"

    # Verify status updated to CONTAINED in DB
    refreshed_inc = db.query(IncidentModel).filter(IncidentModel.incident_id == "inc_rbac_test_001").first()
    assert refreshed_inc.status == "CONTAINED"


def test_get_current_user_profile(auth_client):
    """GET /api/v1/auth/me returns currently authenticated user profile."""
    client, db = auth_client
    analyst = db.query(UserModel).filter(UserModel.username == "analyst").first()
    token = create_access_token(data={"sub": analyst.user_id, "username": analyst.username, "role": analyst.role})

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "analyst"
    assert data["role"] == "ANALYST"
    assert data["email"] == "analyst@aegisai.local"
