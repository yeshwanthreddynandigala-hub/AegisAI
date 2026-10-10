"""
End-to-End Integration and Research Pipeline Tests.
Validates the full workflow from user task to gateway interception, incident correlation,
narrative explanation, and benchmark metric generation.
"""

import pytest
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.security.gateway import gateway
from app.security.correlation_engine import correlation_engine
from app.security.sequence_detector import sequence_detector
from app.security.ml_detector import ml_detector
from app.investigation.explainer import explainer
from app.investigation.threat_intel import threat_correlator
from app.evaluation.benchmark_runner import benchmark_runner
from app.schemas.event import ToolCallRequest

@pytest.fixture
def test_db():
    """In-memory database initialized for end-to-end evaluation."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    # Wire detectors
    correlation_engine.set_detectors(sequence_detector=sequence_detector, ml_detector=ml_detector)
    gateway.set_correlation_engine(correlation_engine)

    yield db
    db.close()

def test_full_pipeline_attack_mitigation_and_investigation(test_db):
    """
    Validates complete 12-step definition of success:
    1. Agent receives task.
    2. Executes normal tool.
    3. Ingests prompt injection payload.
    4. Attempts unauthorized credential read.
    5. Gateway intercepts and blocks BEFORE execution.
    6. Incident is created with evidence linking.
    7. Explainer reconstructs timeline citing exact event IDs.
    """
    agent_id = "agent_sec_test_001"
    session_id = f"sess_{uuid.uuid4().hex[:8]}"

    # Setup agent with least privilege
    agent = AgentModel(
        agent_id=agent_id,
        name="Security Test Agent",
        role="Researcher",
        authorized_objective="Summarize public documentation."
    )
    policy = PolicyManifestModel(
        policy_id=str(uuid.uuid4()),
        agent_id=agent_id,
        allowed_tools=["document_reader", "calculator"],
        allowed_paths=["public/*"],
        denied_paths=["credentials/*", "private/*"],
        allowed_network_domains=["api.internal.mock"],
        allowed_operations=["READ", "CALCULATE"],
        require_approval_operations=["WRITE"],
        max_denial_threshold=3
    )
    test_db.add(agent)
    test_db.add(policy)
    test_db.commit()

    # Step A: Normal authorized read
    resp_benign = gateway.dispatch_tool_call(
        db=test_db,
        request=ToolCallRequest(
            agent_id=agent_id,
            session_id=session_id,
            task_id="task_research",
            tool_name="document_reader",
            parameters={"path": "public/annual_report_2025.txt"}
        )
    )
    assert resp_benign.policy_decision == "ALLOW"
    assert resp_benign.execution_status == "EXECUTED"

    # Step B: Adversarial Prompt Injection attempt -> Unauthorized credential access
    resp_attack = gateway.dispatch_tool_call(
        db=test_db,
        request=ToolCallRequest(
            agent_id=agent_id,
            session_id=session_id,
            task_id="task_research",
            tool_name="document_reader",
            parameters={"path": "credentials/aws_keys.env"},
            source_of_input="INDIRECT_INJECTION"
        )
    )
    # 1. Action MUST be blocked before execution
    assert resp_attack.policy_decision == "DENY"
    assert resp_attack.execution_status == "BLOCKED"
    assert "SENSITIVE_CREDENTIAL_ACCESS" in resp_attack.risk_indicators
    assert resp_attack.output is None

    # 2. Incident MUST be created
    incident = test_db.query(IncidentModel).filter(IncidentModel.session_id == session_id).first()
    assert incident is not None
    assert incident.primary_threat_category == "CREDENTIAL_THEFT"
    assert resp_attack.event_id in incident.evidence_event_ids
    assert incident.mitigation_status == "BLOCKED_AT_GATEWAY"

    # 3. Explainer generates evidence-grounded report citing event IDs
    report_res = explainer.explain_incident(db=test_db, incident_id=incident.incident_id, provider="offline")
    assert report_res["status"] == "success"
    report_text = report_res["report"]
    assert resp_attack.event_id in report_text
    assert "Incident Investigation Dossier" in report_text
    assert "CREDENTIAL_THEFT" in report_text

def test_benchmark_runner_empirical_metrics(test_db):
    """Verifies that the benchmark runs across all scenarios and calculates real metrics."""
    results = benchmark_runner.run_benchmark(db=test_db)

    assert results["total_scenarios"] >= 8
    assert results["attack_count"] >= 4
    assert results["benign_count"] >= 3
    assert results["unseen_count"] >= 2

    comp = results["comparison"]
    for det in ["rule", "sequence", "ml", "combined"]:
        assert det in comp
        assert 0.0 <= comp[det]["precision"] <= 1.0
        assert 0.0 <= comp[det]["recall"] <= 1.0
        assert 0.0 <= comp[det]["f1"] <= 1.0
        assert 0.0 <= comp[det]["fpr"] <= 1.0
        assert 0.0 <= comp[det]["fnr"] <= 1.0
        assert comp[det]["avg_latency_ms"] >= 0.0

    # Blocking effectiveness must be > 0.80
    assert results["blocking_effectiveness"] >= 0.80

def test_threat_intelligence_graph_generation(test_db):
    """Verifies that the threat graph properly links incidents without fake attribution."""
    # Run benchmark first to populate varied incidents
    benchmark_runner.run_benchmark(db=test_db)

    graph = threat_correlator.build_threat_graph(db=test_db)
    assert graph["total_nodes"] > 0
    assert any(n["type"] == "INCIDENT" for n in graph["nodes"])
    assert any(n["type"] == "THREAT_CATEGORY" for n in graph["nodes"])
    
    # Check edges disclaimer
    for e in graph["edges"]:
        if e.get("relationship") == "BEHAVIORAL_SIMILARITY":
            assert "No individual attribution implied" in e.get("attribution_disclaimer", "")
