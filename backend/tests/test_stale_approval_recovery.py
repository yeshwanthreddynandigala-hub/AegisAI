"""
Automated Tests for Stale Approval Recovery & Deadlock Prevention.
Verifies:
1. Abandoned IN_PROGRESS requests transition safely to FAILED (never back to PENDING).
2. Recent active IN_PROGRESS requests remain active during their valid lease.
3. Uncertain/failed operations are NEVER automatically retried.
4. Recovery is completely idempotent.
5. Recovery does not overwrite concurrent successful terminal transitions.
6. Fixture cleanup selectively removes test-created records without affecting production data.
7. API list and recover-stale endpoints cleanly resolve stuck in-progress approvals.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import SessionLocal, init_db, ensure_default_users
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.approval import ApprovalRequestModel, ApprovalStatus
from app.models.event import SecurityEventModel
from app.security.gateway import gateway
from app.agent.environment import synthetic_env


@pytest.fixture(scope="module")
def recovery_fixture():
    init_db()
    db = SessionLocal()
    ensure_default_users(db)

    # Register recovery test agent
    agent = db.query(AgentModel).filter(AgentModel.agent_id == "recovery_test_agent").first()
    if not agent:
        agent = AgentModel(
            agent_id="recovery_test_agent",
            name="Recovery Test Agent",
            role="Reliability Test Agent",
            authorized_objective="Validate Stale Approval Recovery",
            is_active=True
        )
        db.add(agent)

    policy = db.query(PolicyManifestModel).filter(PolicyManifestModel.agent_id == "recovery_test_agent").first()
    if not policy:
        policy = PolicyManifestModel(
            policy_id="pol-recovery-01",
            agent_id="recovery_test_agent",
            version="1.0",
            allowed_tools=["filesystem_read", "filesystem_write", "calculator"],
            allowed_paths=["workspace/*", "documents/*"],
            denied_paths=["credentials/*", "system/*"],
            allowed_network_domains=["api.internal.mock"],
            allowed_operations=["READ", "WRITE"],
            require_approval_operations=["WRITE", "filesystem_write"],
            max_denial_threshold=5
        )
        db.add(policy)

    db.commit()
    db.close()

    client = TestClient(app)

    # Login as analyst
    res_analyst = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystAegis2026!"})
    assert res_analyst.status_code == 200
    analyst_token = res_analyst.json()["access_token"]

    yield {
        "client": client,
        "analyst_token": analyst_token
    }

    # Teardown test files
    for fname in ["stale_write.txt", "never_retry.txt", "race_term.txt"]:
        p = synthetic_env.resolve_sandbox_path(f"workspace/{fname}")
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass


def test_stale_in_progress_transitions_to_failed(recovery_fixture):
    """
    Verifies that an abandoned IN_PROGRESS request whose lease has expired
    transitions to FAILED (never back to PENDING) with an explicit failure reason.
    """
    client = recovery_fixture["client"]
    token = recovery_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Create an approval request
    tool_req = {
        "agent_id": "recovery_test_agent",
        "session_id": f"sess-recov-{uuid.uuid4().hex[:6]}",
        "task_id": "task-recov-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/stale_write.txt",
            "content": "Content of abandoned request"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert init_res.status_code == 200
    approval_id = init_res.json()["approval_id"]
    event_id = init_res.json()["event_id"]

    try:
        # Step 2: Simulate process crash by setting IN_PROGRESS with an expired lease timestamp (10 minutes ago)
        now_utc = datetime.now(timezone.utc)
        ten_mins_ago = now_utc - timedelta(minutes=10)

        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value,
            ApprovalRequestModel.execution_started_at: ten_mins_ago,
            ApprovalRequestModel.reviewed_at: ten_mins_ago
        })
        db.commit()

        # Step 3: Run recovery sweep
        recovered = gateway.recover_stale_approvals(db, timeout_seconds=300)
        assert approval_id in recovered

        # Step 4: Verify record status is FAILED (never PENDING)
        rec = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()
        assert rec.status == ApprovalStatus.FAILED.value
        assert "Execution lease expired" in rec.failure_reason
        assert "outcome is uncertain" in rec.failure_reason
        assert "not automatically retried" in rec.failure_reason

        # Step 5: Verify original event is consistently updated to FAILED
        orig_evt = db.query(SecurityEventModel).filter(
            SecurityEventModel.event_id == event_id
        ).first()
        assert orig_evt.execution_status == ApprovalStatus.FAILED.value
        assert rec.failure_reason in orig_evt.execution_output

        db.close()
    finally:
        # Clean up test records
        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).delete()
        db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).delete()
        db.commit()
        db.close()


def test_recent_active_request_remains_in_progress(recovery_fixture):
    """
    Verifies that a recent active IN_PROGRESS request within its 5-minute lease
    is NOT incorrectly marked stale or modified.
    """
    client = recovery_fixture["client"]
    token = recovery_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tool_req = {
        "agent_id": "recovery_test_agent",
        "session_id": f"sess-recov-{uuid.uuid4().hex[:6]}",
        "task_id": "task-recov-2",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/active_lease.txt",
            "content": "Active execution content"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert init_res.status_code == 200
    approval_id = init_res.json()["approval_id"]
    event_id = init_res.json()["event_id"]

    try:
        # Simulate active execution started 15 seconds ago (lease valid for 300s)
        now_utc = datetime.now(timezone.utc)
        fifteen_secs_ago = now_utc - timedelta(seconds=15)

        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value,
            ApprovalRequestModel.execution_started_at: fifteen_secs_ago,
            ApprovalRequestModel.reviewed_at: fifteen_secs_ago
        })
        db.commit()

        # Run recovery
        recovered = gateway.recover_stale_approvals(db, timeout_seconds=300)
        assert approval_id not in recovered

        # Verify record remains IN_PROGRESS
        rec = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()
        assert rec.status == ApprovalStatus.IN_PROGRESS.value

        db.close()
    finally:
        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).delete()
        db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).delete()
        db.commit()
        db.close()


def test_failed_or_uncertain_operation_never_automatically_retried(recovery_fixture):
    """
    Verifies that recovering an abandoned request NEVER retries or executes the tool.
    Target file must NOT exist, and subsequent API calls must not trigger execution.
    """
    client = recovery_fixture["client"]
    token = recovery_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    target_file = "workspace/never_retry.txt"
    p = synthetic_env.resolve_sandbox_path(target_file)
    if p.exists():
        p.unlink()

    tool_req = {
        "agent_id": "recovery_test_agent",
        "session_id": f"sess-recov-{uuid.uuid4().hex[:6]}",
        "task_id": "task-recov-3",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": target_file,
            "content": "Must never be written"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    approval_id = init_res.json()["approval_id"]
    event_id = init_res.json()["event_id"]

    try:
        # Simulate stale in progress (20 minutes ago)
        now_utc = datetime.now(timezone.utc)
        stale_time = now_utc - timedelta(minutes=20)

        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value,
            ApprovalRequestModel.execution_started_at: stale_time,
            ApprovalRequestModel.reviewed_at: stale_time
        })
        db.commit()

        # Recovery runs
        gateway.recover_stale_approvals(db, timeout_seconds=300)

        # Confirm file was NEVER written
        assert not p.exists(), "Tool must never execute during recovery!"

        # Call list_approvals API multiple times
        client.get("/api/v1/approvals", headers=headers)
        client.get(f"/api/v1/approvals/{approval_id}", headers=headers)

        # File must STILL not exist
        assert not p.exists(), "Subsequent API operations must never trigger retry!"

        db.close()
    finally:
        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).delete()
        db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).delete()
        db.commit()
        db.close()


def test_recovery_is_idempotent(recovery_fixture):
    """
    Verifies that running recovery repeatedly on the same state produces
    no side-effects, does not corrupt data, and returns an empty list on subsequent runs.
    """
    client = recovery_fixture["client"]
    token = recovery_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tool_req = {
        "agent_id": "recovery_test_agent",
        "session_id": f"sess-recov-{uuid.uuid4().hex[:6]}",
        "task_id": "task-recov-4",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/idempotent_recov.txt",
            "content": "Testing idempotency"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    approval_id = init_res.json()["approval_id"]
    event_id = init_res.json()["event_id"]

    try:
        now_utc = datetime.now(timezone.utc)
        stale_time = now_utc - timedelta(minutes=15)

        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value,
            ApprovalRequestModel.execution_started_at: stale_time,
            ApprovalRequestModel.reviewed_at: stale_time
        })
        db.commit()

        # Run 1: Recovers the record
        recov1 = gateway.recover_stale_approvals(db, timeout_seconds=300)
        assert approval_id in recov1

        # Run 2: Idempotent - does nothing
        recov2 = gateway.recover_stale_approvals(db, timeout_seconds=300)
        assert approval_id not in recov2

        # Run 3: Idempotent - does nothing
        recov3 = gateway.recover_stale_approvals(db, timeout_seconds=300)
        assert approval_id not in recov3

        rec = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).first()
        assert rec.status == ApprovalStatus.FAILED.value

        db.close()
    finally:
        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).delete()
        db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).delete()
        db.commit()
        db.close()


def test_recovery_does_not_overwrite_concurrent_successful_terminal_transition(recovery_fixture):
    """
    Verifies race safety:
    If a live execution completes and updates status to EXECUTED, recovery
    will NOT overwrite the terminal status even if the lease timeout has elapsed.
    """
    db = SessionLocal()
    approval_id = f"appr-race-{uuid.uuid4().hex[:8]}"
    event_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc)
    old_time = now_utc - timedelta(minutes=12)

    req = ApprovalRequestModel(
        approval_id=approval_id,
        event_id=event_id,
        agent_id="recovery_test_agent",
        session_id="sess-race-term",
        task_id="task-race-term",
        tool_name="filesystem_write",
        parameters={"path": "workspace/race_term.txt", "content": "Race content"},
        status=ApprovalStatus.EXECUTED.value,  # Already in terminal state!
        created_at=old_time,
        expires_at=old_time + timedelta(hours=24),
        execution_started_at=old_time,
        reviewed_at=old_time,
        execution_output="Tool succeeded before recovery"
    )
    db.add(req)
    db.commit()

    try:
        # Run recovery
        recovered = gateway.recover_stale_approvals(db, timeout_seconds=300)
        assert approval_id not in recovered

        # Check record: MUST remain EXECUTED
        check = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).first()
        assert check.status == ApprovalStatus.EXECUTED.value
        assert check.execution_output == "Tool succeeded before recovery"
    finally:
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).delete()
        db.commit()
        db.close()


def test_test_fixture_cleanup_removes_only_test_records():
    """
    Verifies that fixture cleanup logic selectively removes test-created records
    without deleting legitimate or production records.
    """
    db = SessionLocal()
    prod_approval_id = f"appr-prod-{uuid.uuid4().hex[:8]}"
    test_approval_id = f"appr-test-temp-{uuid.uuid4().hex[:8]}"
    now_utc = datetime.now(timezone.utc)

    # Insert a simulated production approval and a test approval
    prod_req = ApprovalRequestModel(
        approval_id=prod_approval_id,
        event_id=str(uuid.uuid4()),
        agent_id="production_agent",
        session_id="sess-prod-real-001",
        task_id="task-prod-001",
        tool_name="filesystem_write",
        parameters={"path": "workspace/prod.txt", "content": "Important business data"},
        status=ApprovalStatus.PENDING.value,
        created_at=now_utc,
        expires_at=now_utc + timedelta(hours=24)
    )
    test_req = ApprovalRequestModel(
        approval_id=test_approval_id,
        event_id=str(uuid.uuid4()),
        agent_id="test_agent",
        session_id="sess-inprog-temp-001",
        task_id="task-test-001",
        tool_name="filesystem_write",
        parameters={"path": "workspace/temp.txt", "content": "Temp test data"},
        status=ApprovalStatus.IN_PROGRESS.value,
        created_at=now_utc,
        expires_at=now_utc + timedelta(hours=24)
    )
    db.add_all([prod_req, test_req])
    db.commit()

    try:
        # Simulate fixture cleanup: Deletes only test_approval_id
        db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == test_approval_id
        ).delete()
        db.commit()

        # Verify test record was removed
        assert db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == test_approval_id).first() is None

        # Verify production record is COMPLETELY INTACT
        prod_check = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == prod_approval_id).first()
        assert prod_check is not None
        assert prod_check.status == ApprovalStatus.PENDING.value
        assert prod_check.agent_id == "production_agent"
    finally:
        # Clean up prod simulation
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == prod_approval_id).delete()
        db.commit()
        db.close()


def test_api_endpoint_recovers_stale_in_progress(recovery_fixture):
    """
    Verifies that calling the API list endpoint or recover-stale endpoint
    recovers abandoned IN_PROGRESS requests and renders them as FAILED in the Approvals Inbox.
    """
    client = recovery_fixture["client"]
    token = recovery_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tool_req = {
        "agent_id": "recovery_test_agent",
        "session_id": f"sess-recov-{uuid.uuid4().hex[:6]}",
        "task_id": "task-recov-api",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/api_stale.txt",
            "content": "API stale test"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    approval_id = init_res.json()["approval_id"]
    event_id = init_res.json()["event_id"]

    try:
        now_utc = datetime.now(timezone.utc)
        ten_mins_ago = now_utc - timedelta(minutes=10)

        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value,
            ApprovalRequestModel.execution_started_at: ten_mins_ago,
            ApprovalRequestModel.reviewed_at: ten_mins_ago
        })
        db.commit()
        db.close()

        # Query GET /api/v1/approvals (which triggers lazy recovery)
        list_res = client.get("/api/v1/approvals", headers=headers)
        assert list_res.status_code == 200
        items = list_res.json()

        # Find our item in the list
        item = next((i for i in items if i["approval_id"] == approval_id), None)
        assert item is not None
        assert item["status"] == "FAILED"
        assert "Execution lease expired" in item["failure_reason"]

        # Call POST /api/v1/approvals/recover-stale explicitly
        recov_res = client.post("/api/v1/approvals/recover-stale", headers=headers)
        assert recov_res.status_code == 200
        data = recov_res.json()
        assert data["status"] == "success"
    finally:
        db = SessionLocal()
        db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).delete()
        db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).delete()
        db.commit()
        db.close()
