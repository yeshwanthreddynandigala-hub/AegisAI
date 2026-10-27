"""
FastAPI TestClient Integration Tests for AegisAI API Endpoints.
Verifies all core REST endpoints with zero-trust gateway mediation,
telemetry filtering, incident investigations, simulation execution, and threat graph generation.
Operates on an isolated in-memory SQLite database using StaticPool.
"""

import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.config import settings
from app.core.database import Base, get_db
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.models.user import UserModel, UserRole
from app.core.database import ensure_default_users
from app.core.security import create_access_token
from app.security.gateway import gateway
from app.security.correlation_engine import correlation_engine
from app.security.sequence_detector import sequence_detector
from app.security.ml_detector import ml_detector
from app.evaluation.benchmark_runner import _ensure_benchmark_agents


@pytest.fixture
def client_and_db():
    """Provides isolated TestClient and in-memory test database."""
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
    correlation_engine.set_detectors(sequence_detector=sequence_detector, ml_detector=ml_detector)
    gateway.set_correlation_engine(correlation_engine)

    # Issue admin token for default authorized requests
    admin = db.query(UserModel).filter(UserModel.username == "admin").first()
    token = create_access_token(data={"sub": admin.user_id, "username": admin.username, "role": admin.role})

    def _override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {token}"
        yield c, db

    app.dependency_overrides.clear()
    db.close()


def test_health_check(client_and_db):
    """GET /api/v1/health returns 200 with service status."""
    client, _ = client_and_db
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "Security" in data["service"]
    assert "version" in data


def test_overview_statistics(client_and_db):
    """GET /api/v1/overview/stats returns telemetry counts and breakdown."""
    client, _ = client_and_db
    resp = client.get("/api/v1/overview/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "monitored_agents_count" in data
    assert data["monitored_agents_count"] >= 2
    assert "security_events_count" in data
    assert "blocked_operations_count" in data
    assert "recent_incidents" in data
    assert "recent_events" in data


def test_agents_list_and_get(client_and_db):
    """GET /api/v1/agents and GET /api/v1/agents/{agent_id}."""
    client, _ = client_and_db

    # List all agents
    resp = client.get("/api/v1/agents")
    assert resp.status_code == 200
    agents = resp.json()
    assert len(agents) >= 2
    agent_ids = [a["agent_id"] for a in agents]
    assert "agent_researcher_001" in agent_ids

    # Get existing agent
    resp_one = client.get("/api/v1/agents/agent_researcher_001")
    assert resp_one.status_code == 200
    ag_data = resp_one.json()
    assert ag_data["agent_id"] == "agent_researcher_001"
    assert ag_data["policy"] is not None
    assert "public/*" in ag_data["policy"]["allowed_paths"]

    # Nonexistent agent 404
    resp_none = client.get("/api/v1/agents/nonexistent_agent_999")
    assert resp_none.status_code == 404


def test_agent_registration(client_and_db):
    """POST /api/v1/agents registers a new monitored agent and policy."""
    client, _ = client_and_db
    new_agent_payload = {
        "agent_id": "agent_test_api_001",
        "name": "API Test Agent",
        "role": "Security QA",
        "description": "Agent created via automated API test.",
        "authorized_objective": "Test API registrations.",
        "is_active": True,
        "policy": {
            "version": "1.0",
            "allowed_tools": ["calculator"],
            "allowed_paths": ["public/*"],
            "denied_paths": ["credentials/*"],
            "allowed_network_domains": [],
            "allowed_operations": ["CALCULATE"],
            "require_approval_operations": [],
            "max_denial_threshold": 3
        }
    }

    # First creation succeeds
    resp = client.post("/api/v1/agents", json=new_agent_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "agent_test_api_001"
    assert data["policy"]["allowed_tools"] == ["calculator"]

    # Duplicate creation returns 400
    resp_dup = client.post("/api/v1/agents", json=new_agent_payload)
    assert resp_dup.status_code == 400
    assert "already exists" in resp_dup.json()["detail"]


def test_gateway_tool_execution_allowed_and_denied(client_and_db):
    """POST /api/v1/events/execute dispatches through Zero-Trust Gateway."""
    client, _ = client_and_db
    session_id = f"sess_api_{uuid.uuid4().hex[:8]}"

    # 1. Benign authorized tool invocation
    req_allowed = {
        "agent_id": "agent_researcher_001",
        "session_id": session_id,
        "task_id": "task_api_read",
        "tool_name": "document_reader",
        "parameters": {"path": "public/annual_report_2025.txt"},
        "source_of_input": "DIRECT_AGENT"
    }
    resp_allow = client.post("/api/v1/events/execute", json=req_allowed)
    assert resp_allow.status_code == 200
    d_allow = resp_allow.json()
    assert d_allow["policy_decision"] == "ALLOW"
    assert d_allow["execution_status"] == "EXECUTED"
    assert d_allow["output"] is not None

    # 2. Unauthorized credential probe blocked pre-execution
    req_denied = {
        "agent_id": "agent_researcher_001",
        "session_id": session_id,
        "task_id": "task_api_probe",
        "tool_name": "document_reader",
        "parameters": {"path": "credentials/aws_keys.env"},
        "source_of_input": "DIRECT_AGENT"
    }
    resp_deny = client.post("/api/v1/events/execute", json=req_denied)
    assert resp_deny.status_code == 200
    d_deny = resp_deny.json()
    assert d_deny["policy_decision"] == "DENY"
    assert d_deny["execution_status"] == "BLOCKED"
    assert d_deny["output"] is None
    assert "SENSITIVE_CREDENTIAL_ACCESS" in d_deny["risk_indicators"]


def test_events_list_and_get(client_and_db):
    """GET /api/v1/events and GET /api/v1/events/{event_id} with query filters."""
    client, _ = client_and_db
    session_id = f"sess_evt_{uuid.uuid4().hex[:8]}"

    # Execute a tool to ensure an event is recorded
    client.post("/api/v1/events/execute", json={
        "agent_id": "agent_researcher_001",
        "session_id": session_id,
        "task_id": "task_evt",
        "tool_name": "document_reader",
        "parameters": {"path": "public/annual_report_2025.txt"},
        "source_of_input": "DIRECT_AGENT"
    })

    # List events with session filter
    resp = client.get(f"/api/v1/events?session_id={session_id}")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 1
    event_id = events[0]["event_id"]

    # Get event by ID
    resp_single = client.get(f"/api/v1/events/{event_id}")
    assert resp_single.status_code == 200
    assert resp_single.json()["event_id"] == event_id

    # Nonexistent event returns 404
    resp_404 = client.get(f"/api/v1/events/invalid_event_id_999")
    assert resp_404.status_code == 404


def test_incidents_and_investigation_flow(client_and_db):
    """GET /api/v1/incidents, GET /api/v1/incidents/{id}, and POST /api/v1/incidents/{id}/investigate."""
    client, _ = client_and_db
    session_id = f"sess_inc_{uuid.uuid4().hex[:8]}"

    # Trigger policy violation to generate an incident
    client.post("/api/v1/events/execute", json={
        "agent_id": "agent_researcher_001",
        "session_id": session_id,
        "task_id": "task_attack",
        "tool_name": "document_reader",
        "parameters": {"path": "credentials/aws_keys.env"},
        "source_of_input": "DIRECT_AGENT"
    })

    # Fetch incident list
    resp_inc = client.get("/api/v1/incidents")
    assert resp_inc.status_code == 200
    incidents = resp_inc.json()
    assert len(incidents) >= 1

    matched_inc = next((inc for inc in incidents if inc["session_id"] == session_id), None)
    assert matched_inc is not None
    incident_id = matched_inc["incident_id"]

    # Fetch incident detail with timeline
    resp_det = client.get(f"/api/v1/incidents/{incident_id}")
    assert resp_det.status_code == 200
    detail = resp_det.json()
    assert detail["incident_id"] == incident_id
    assert len(detail["timeline_events"]) >= 1

    # Trigger offline investigation narrative generation
    resp_inv = client.post(f"/api/v1/incidents/{incident_id}/investigate", json={"provider": "offline"})
    assert resp_inv.status_code == 200
    inv_data = resp_inv.json()
    assert inv_data["status"] == "success"
    assert "Incident Investigation Dossier" in inv_data["report"]
    assert incident_id in inv_data["report"]


def test_simulations_catalog_and_execution(client_and_db):
    """GET /api/v1/simulations/scenarios and POST /api/v1/simulations/run/{scenario_id}."""
    client, _ = client_and_db

    # List scenarios
    resp_list = client.get("/api/v1/simulations/scenarios")
    assert resp_list.status_code == 200
    scenarios = resp_list.json()
    assert len(scenarios) >= 5

    # Run known scenario
    resp_run = client.post("/api/v1/simulations/run/BENIGN_02_CATALOG_SEARCH")
    assert resp_run.status_code == 200
    result = resp_run.json()
    assert result["scenario_id"] == "BENIGN_02_CATALOG_SEARCH"
    assert result["total_steps"] == 2
    assert result["blocked_steps"] == 0
    assert result["gateway_protected_safely"] is True

    # Run nonexistent scenario returns 404
    resp_invalid = client.post("/api/v1/simulations/run/NONEXISTENT_SCENARIO_999")
    assert resp_invalid.status_code == 404


def test_threat_intel_graph(client_and_db):
    """GET /api/v1/threat-intel/graph returns graph nodes and edges."""
    client, _ = client_and_db
    resp = client.get("/api/v1/threat-intel/graph")
    assert resp.status_code == 200
    graph = resp.json()
    assert "nodes" in graph
    assert "edges" in graph
    assert "total_nodes" in graph
    assert "total_edges" in graph
