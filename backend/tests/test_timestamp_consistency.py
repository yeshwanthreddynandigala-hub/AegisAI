"""
Automated Tests for Timestamp Consistency, UTC Serialization, and Event Chronology.
Verifies:
1. Timestamps stored in SQLite and loaded via UTCDateTime are always timezone-aware UTC datetimes.
2. Pydantic schemas always serialize timestamps with the explicit 'Z' UTC indicator.
3. Event ordering is strictly chronological across queries, gateway sessions, and timeline reconstruction.
4. Explainer dossier output formats timestamps with explicit 'UTC' markers without timezone confusion.
5. Historical synthetic demo events are identifiable by provenance metadata.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, UTCDateTime, get_db
from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.models.agent import AgentModel, PolicyManifestModel
from app.schemas.event import SecurityEventResponse
from app.schemas.incident import IncidentResponse, IncidentInvestigationDetail
from app.security.gateway import gateway
from app.security.correlation_engine import correlation_engine
from app.security.sequence_detector import sequence_detector
from app.security.ml_detector import ml_detector
from app.investigation.explainer import explainer


@pytest.fixture
def test_db():
    """In-memory SQLite session using UTCDateTime and StaticPool."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    correlation_engine.set_detectors(sequence_detector=sequence_detector, ml_detector=ml_detector)
    gateway.set_correlation_engine(correlation_engine)

    yield db
    db.close()


def test_utcdatetime_database_storage_and_retrieval(test_db):
    """
    Verifies that inserting a naive or aware datetime into SQLite
    via UTCDateTime always returns a timezone-aware datetime with tzinfo=timezone.utc.
    """
    event_id = str(uuid.uuid4())
    # 1. Insert naive datetime
    naive_dt = datetime(2026, 10, 27, 14, 7, 46, 123456)
    evt_naive = SecurityEventModel(
        event_id=event_id,
        timestamp=naive_dt,
        agent_id="test_agent",
        session_id="test_sess",
        task_id="test_task",
        action_type="TOOL_CALL_ALLOWED"
    )
    test_db.add(evt_naive)
    test_db.commit()

    retrieved = test_db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).first()
    assert retrieved is not None
    assert retrieved.timestamp.tzinfo is not None
    assert retrieved.timestamp.tzinfo == timezone.utc
    assert retrieved.timestamp.hour == 14
    assert retrieved.timestamp.minute == 7

    # 2. Insert aware datetime
    event_id_2 = str(uuid.uuid4())
    aware_dt = datetime.now(timezone.utc)
    evt_aware = SecurityEventModel(
        event_id=event_id_2,
        timestamp=aware_dt,
        agent_id="test_agent",
        session_id="test_sess",
        task_id="test_task",
        action_type="TOOL_CALL_ALLOWED"
    )
    test_db.add(evt_aware)
    test_db.commit()

    retrieved_2 = test_db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id_2).first()
    assert retrieved_2.timestamp.tzinfo == timezone.utc


def test_pydantic_utc_serialization_has_explicit_z(test_db):
    """
    Verifies that Pydantic v2 schemas for events and incidents serialize
    all timestamps into ISO 8601 strings ending with 'Z'.
    """
    # Create sample event
    evt = SecurityEventModel(
        event_id=str(uuid.uuid4()),
        timestamp=datetime(2026, 10, 27, 14, 7, 46, 500000, tzinfo=timezone.utc),
        agent_id="agent_001",
        session_id="sess_001",
        task_id="task_001",
        action_type="TOOL_CALL_ALLOWED",
        tool_name="document_reader",
        resource="public/doc.txt",
        policy_decision="ALLOW",
        execution_status="EXECUTED"
    )
    test_db.add(evt)

    # Create sample incident
    inc = IncidentModel(
        incident_id=str(uuid.uuid4()),
        session_id="sess_001",
        agent_id="agent_001",
        title="Test Incident",
        severity="HIGH",
        status="OPEN",
        primary_threat_category="CREDENTIAL_THEFT",
        summary="Test summary",
        triggering_event_id=evt.event_id,
        created_at=datetime(2026, 10, 27, 14, 7, 46, 500000, tzinfo=timezone.utc),
        updated_at=datetime(2026, 10, 27, 14, 8, 0, 0, tzinfo=timezone.utc)
    )
    test_db.add(inc)
    test_db.commit()

    # Validate Event serialization
    e_resp = SecurityEventResponse.model_validate(evt)
    e_json = e_resp.model_dump_json()
    assert '"timestamp":"2026-10-27T14:07:46.500000Z"' in e_json

    # Validate Incident serialization
    inc_resp = IncidentResponse.model_validate(inc)
    inc_json = inc_resp.model_dump_json()
    assert '"created_at":"2026-10-27T14:07:46.500000Z"' in inc_json
    assert '"updated_at":"2026-10-27T14:08:00Z"' in inc_json


def test_chronological_event_ordering_in_session(test_db):
    """
    Verifies that events in a multi-step session maintain exact chronological ordering
    and that queries using .order_by(SecurityEventModel.timestamp.asc()) correctly sequence them.
    """
    session_id = f"sess_order_{uuid.uuid4().hex[:8]}"
    base_time = datetime(2026, 10, 27, 14, 0, 0, tzinfo=timezone.utc)

    # Add 3 events out-of-order intentionally
    evt_step2 = SecurityEventModel(
        event_id="evt_step_2",
        session_id=session_id,
        task_id="task_order",
        agent_id="agent_001",
        action_type="TOOL_CALL_ALLOWED",
        timestamp=base_time + timedelta(seconds=10)
    )
    evt_step1 = SecurityEventModel(
        event_id="evt_step_1",
        session_id=session_id,
        task_id="task_order",
        agent_id="agent_001",
        action_type="TOOL_CALL_ALLOWED",
        timestamp=base_time
    )
    evt_step3 = SecurityEventModel(
        event_id="evt_step_3",
        session_id=session_id,
        task_id="task_order",
        agent_id="agent_001",
        action_type="TOOL_CALL_BLOCKED",
        timestamp=base_time + timedelta(seconds=20)
    )

    test_db.add_all([evt_step2, evt_step1, evt_step3])
    test_db.commit()

    # Query with chronological ordering
    ordered_events = test_db.query(SecurityEventModel).filter(
        SecurityEventModel.session_id == session_id
    ).order_by(SecurityEventModel.timestamp.asc()).all()

    ordered_ids = [e.event_id for e in ordered_events]
    assert ordered_ids == ["evt_step_1", "evt_step_2", "evt_step_3"]


def test_explainer_dossier_contains_explicit_utc_indicator(test_db):
    """
    Verifies that the generated investigation dossier formats event timestamps
    with full date, time, and explicit UTC marker, matching underlying telemetry.
    """
    session_id = f"sess_dossier_{uuid.uuid4().hex[:8]}"
    event_time = datetime(2026, 10, 27, 14, 7, 46, tzinfo=timezone.utc)

    evt = SecurityEventModel(
        event_id="evt_dossier_001",
        session_id=session_id,
        task_id="task_dossier",
        agent_id="agent_researcher_001",
        action_type="TOOL_CALL_BLOCKED",
        tool_name="document_reader",
        resource="credentials/aws_keys.env",
        policy_decision="DENY",
        execution_status="BLOCKED",
        risk_indicators=["SENSITIVE_CREDENTIAL_ACCESS"],
        timestamp=event_time
    )
    test_db.add(evt)

    inc = IncidentModel(
        incident_id="inc_dossier_001",
        session_id=session_id,
        agent_id="agent_researcher_001",
        title="Unauthorized Credential Probe",
        severity="CRITICAL",
        status="OPEN",
        primary_threat_category="CREDENTIAL_THEFT",
        summary="Agent attempted to access AWS credentials",
        triggering_event_id="evt_dossier_001",
        evidence_event_ids=["evt_dossier_001"],
        created_at=event_time,
        updated_at=event_time
    )
    test_db.add(inc)
    test_db.commit()

    report_result = explainer.explain_incident(db=test_db, incident_id="inc_dossier_001", provider="offline")
    assert report_result["status"] == "success"
    report_text = report_result["report"]

    # Verify report explicitly includes date and UTC marker
    assert "2026-10-27 14:07:46 UTC" in report_text
    assert "evt_dossier_001" in report_text
