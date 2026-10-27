"""
Comprehensive Automated Tests for Phase 3: Human-in-the-Loop (HITL) Approval Workflow.
Verifies:
1. Pausing of sensitive operations before execution with persistent approval requests.
2. Zero-trust policy revalidation and safe execution lifecycle upon authorized approval.
3. Strict enforcement that rejected or expired operations never execute.
4. Idempotency and replay prevention (duplicate decisions rejected).
5. Unauthenticated rejection (HTTP 401).
6. Agent deactivation / policy violation prevents execution.
7. Full audit trail with reviewer identity, timestamp, and decision reason.
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
from app.models.user import UserModel
from app.agent.environment import synthetic_env


@pytest.fixture(scope="module")
def client_and_auth():
    init_db()
    db = SessionLocal()
    ensure_default_users(db)

    # Ensure an agent with WRITE approval policy exists
    test_agent = db.query(AgentModel).filter(AgentModel.agent_id == "hitl_test_agent").first()
    if not test_agent:
        test_agent = AgentModel(
            agent_id="hitl_test_agent",
            name="HITL Test Agent",
            role="Research Assistant",
            authorized_objective="Perform filesystem writes with human approval",
            is_active=True
        )
        db.add(test_agent)

    test_policy = db.query(PolicyManifestModel).filter(PolicyManifestModel.agent_id == "hitl_test_agent").first()
    if not test_policy:
        test_policy = PolicyManifestModel(
            policy_id="pol-hitl-01",
            agent_id="hitl_test_agent",
            version="1.0",
            allowed_tools=["filesystem_read", "filesystem_write", "calculator"],
            allowed_paths=["documents/*", "reports/*", "workspace/*"],
            denied_paths=["credentials/*", "system/*"],
            allowed_network_domains=["api.internal.mock"],
            allowed_operations=["READ", "WRITE"],
            require_approval_operations=["WRITE", "filesystem_write"],
            max_denial_threshold=3
        )
        db.add(test_policy)
    else:
        test_policy.require_approval_operations = ["WRITE", "filesystem_write"]
        test_policy.allowed_paths = ["documents/*", "reports/*", "workspace/*"]

    db.commit()
    db.close()

    client = TestClient(app)

    # Login as admin
    res_admin = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminAegis2026!"})
    assert res_admin.status_code == 200
    admin_token = res_admin.json()["access_token"]

    # Login as analyst
    res_analyst = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystAegis2026!"})
    assert res_analyst.status_code == 200
    analyst_token = res_analyst.json()["access_token"]

    yield {
        "client": client,
        "admin_token": admin_token,
        "analyst_token": analyst_token
    }

    # Teardown: Clean up any files created during test executions
    for filename in [
        "hitl_pause_test.txt",
        "hitl_approved_execution.txt",
        "hitl_rejected_file.txt",
        "idempotent_test.txt",
        "expired_test.txt",
        "deactivated_agent_test.txt"
    ]:
        p = synthetic_env.resolve_sandbox_path(f"workspace/{filename}")
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass


def test_sensitive_operation_paused_and_creates_approval_request(client_and_auth):
    """
    Submitting a filesystem_write for an agent with WRITE in require_approval_operations
    must be paused as REQUIRE_APPROVAL and PENDING, and create a persistent ApprovalRequestModel.
    The file must NOT exist on the filesystem yet.
    """
    client = client_and_auth["client"]
    analyst_token = client_and_auth["analyst_token"]
    headers = {"Authorization": f"Bearer {analyst_token}"}

    target_file = "workspace/hitl_pause_test.txt"
    resolved_path = synthetic_env.resolve_sandbox_path(target_file)
    if resolved_path.exists():
        resolved_path.unlink()

    payload = {
        "agent_id": "hitl_test_agent",
        "session_id": f"sess-hitl-pause-{uuid.uuid4().hex[:8]}",
        "task_id": "task-01",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": target_file,
            "content": "Secret content pending human review"
        }
    }

    res = client.post("/api/v1/events/execute", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["policy_decision"] == "REQUIRE_APPROVAL"
    assert data["execution_status"] == "PENDING"
    assert data["output"] is None
    assert "approval_id" in data
    assert data["approval_id"] is not None

    approval_id = data["approval_id"]

    # Verify that tool was NOT executed (file must NOT exist yet!)
    assert not resolved_path.exists(), "Tool must not execute while pending human approval!"

    # Verify persistent approval request exists via API
    get_res = client.get(f"/api/v1/approvals/{approval_id}", headers=headers)
    assert get_res.status_code == 200
    appr_data = get_res.json()
    assert appr_data["approval_id"] == approval_id
    assert appr_data["status"] == "PENDING"
    assert appr_data["tool_name"] == "filesystem_write"
    assert appr_data["parameters"]["path"] == target_file
    assert appr_data["reviewed_by_username"] is None


def test_authorized_analyst_approval_executes_tool_safely(client_and_auth):
    """
    An authorized reviewer approving a pending request must:
    1. Revalidate policy against the agent manifest.
    2. Execute the tool in the sandbox (file is created).
    3. Transition status to EXECUTED.
    4. Record reviewer identity, timestamp, and justification.
    """
    client = client_and_auth["client"]
    analyst_token = client_and_auth["analyst_token"]
    headers = {"Authorization": f"Bearer {analyst_token}"}

    target_file = "workspace/hitl_approved_execution.txt"
    resolved_path = synthetic_env.resolve_sandbox_path(target_file)
    if resolved_path.exists():
        resolved_path.unlink()

    # Step 1: Request tool execution that requires approval
    payload = {
        "agent_id": "hitl_test_agent",
        "session_id": f"sess-hitl-approve-{uuid.uuid4().hex[:8]}",
        "task_id": "task-02",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": target_file,
            "content": "Approved payload successfully executed"
        }
    }
    exec_res = client.post("/api/v1/events/execute", json=payload, headers=headers)
    assert exec_res.status_code == 200
    approval_id = exec_res.json()["approval_id"]
    assert not resolved_path.exists()

    # Step 2: Analyst approves the request
    decision_payload = {
        "justification": "Verified file content conforms to operational policy."
    }
    appr_res = client.post(f"/api/v1/approvals/{approval_id}/approve", json=decision_payload, headers=headers)
    assert appr_res.status_code == 200
    result = appr_res.json()

    assert result["status"] == "EXECUTED"
    assert result["reviewed_by_username"] == "analyst"
    assert result["review_justification"] == "Verified file content conforms to operational policy."
    assert result["reviewed_at"] is not None
    assert "bytes_written" in (result["execution_output"] or "")

    # Step 3: Verify the tool ACTUALLY executed in the synthetic environment!
    assert resolved_path.exists(), "File must exist on disk after approved execution!"
    assert resolved_path.read_text(encoding="utf-8") == "Approved payload successfully executed"


def test_rejection_prevents_tool_execution(client_and_auth):
    """
    A rejected approval request must:
    1. Transition status to REJECTED.
    2. NEVER execute the tool (file is not created).
    3. Update the original audit event to BLOCKED.
    """
    client = client_and_auth["client"]
    admin_token = client_and_auth["admin_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    target_file = "workspace/hitl_rejected_file.txt"
    resolved_path = synthetic_env.resolve_sandbox_path(target_file)
    if resolved_path.exists():
        resolved_path.unlink()

    # Step 1: Request tool execution that requires approval
    payload = {
        "agent_id": "hitl_test_agent",
        "session_id": f"sess-hitl-reject-{uuid.uuid4().hex[:8]}",
        "task_id": "task-03",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": target_file,
            "content": "Malicious content intended for exfiltration"
        }
    }
    exec_res = client.post("/api/v1/events/execute", json=payload, headers=headers)
    assert exec_res.status_code == 200
    approval_id = exec_res.json()["approval_id"]

    # Step 2: Admin rejects the request
    rejection_payload = {
        "justification": "Writing unauthorized data rejected by Security Administrator."
    }
    reject_res = client.post(f"/api/v1/approvals/{approval_id}/reject", json=rejection_payload, headers=headers)
    assert reject_res.status_code == 200
    data = reject_res.json()

    assert data["status"] == "REJECTED"
    assert data["reviewed_by_username"] == "admin"
    assert "Writing unauthorized data rejected" in data["review_justification"]
    assert data["execution_output"] is None

    # Step 3: Tool must NOT have run
    assert not resolved_path.exists(), "Rejected tool call must NEVER create files or execute!"


def test_expired_approval_cannot_be_approved(client_and_auth):
    """
    An expired approval request cannot be approved or executed; returns HTTP 400.
    """
    client = client_and_auth["client"]
    admin_token = client_and_auth["admin_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create request and manually simulate expiration
    payload = {
        "agent_id": "hitl_test_agent",
        "session_id": f"sess-hitl-expire-{uuid.uuid4().hex[:8]}",
        "task_id": "task-04",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/expired_test.txt",
            "content": "Expired content"
        }
    }
    exec_res = client.post("/api/v1/events/execute", json=payload, headers=headers)
    approval_id = exec_res.json()["approval_id"]

    # Backdate expires_at in DB
    db = SessionLocal()
    appr = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.approval_id == approval_id).first()
    appr.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()
    db.close()

    # Attempt to approve
    approve_res = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"justification": "Attempting to approve expired task"},
        headers=headers
    )
    assert approve_res.status_code == 400
    assert "expired" in approve_res.text.lower()


def test_duplicate_decisions_prevented(client_and_auth):
    """
    A request that has already been approved and executed cannot be approved or rejected again.
    """
    client = client_and_auth["client"]
    admin_token = client_and_auth["admin_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    payload = {
        "agent_id": "hitl_test_agent",
        "session_id": f"sess-hitl-idempotent-{uuid.uuid4().hex[:8]}",
        "task_id": "task-05",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/idempotent_test.txt",
            "content": "Once only"
        }
    }
    exec_res = client.post("/api/v1/events/execute", json=payload, headers=headers)
    approval_id = exec_res.json()["approval_id"]

    # First approval succeeds
    appr1 = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"justification": "First legitimate approval"},
        headers=headers
    )
    assert appr1.status_code == 200

    # Second approval attempt must fail
    appr2 = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"justification": "Replay attempt"},
        headers=headers
    )
    assert appr2.status_code == 400
    assert "already been processed" in appr2.text.lower()

    # Reject attempt on executed request must also fail
    reject_attempt = client.post(
        f"/api/v1/approvals/{approval_id}/reject",
        json={"justification": "Attempt to reject already executed action"},
        headers=headers
    )
    assert reject_attempt.status_code == 400


def test_unauthenticated_request_rejected(client_and_auth):
    """Requests without valid JWT tokens must receive HTTP 401."""
    client = client_and_auth["client"]

    res = client.get("/api/v1/approvals")
    assert res.status_code == 401

    res_post = client.post(
        "/api/v1/approvals/appr-fake/approve",
        json={"justification": "No auth"}
    )
    assert res_post.status_code == 401


def test_policy_revalidation_fails_if_agent_deactivated(client_and_auth):
    """
    If an agent is deactivated between request time and approval time,
    revalidation fails with HTTP 400 and the tool is NOT executed.
    """
    client = client_and_auth["client"]
    admin_token = client_and_auth["admin_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    target_file = "workspace/deactivated_agent_test.txt"
    resolved_path = synthetic_env.resolve_sandbox_path(target_file)
    if resolved_path.exists():
        resolved_path.unlink()

    # Step 1: Create approval request
    payload = {
        "agent_id": "hitl_test_agent",
        "session_id": f"sess-hitl-deactivate-{uuid.uuid4().hex[:8]}",
        "task_id": "task-06",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": target_file,
            "content": "Should not execute because agent will be deactivated"
        }
    }
    exec_res = client.post("/api/v1/events/execute", json=payload, headers=headers)
    approval_id = exec_res.json()["approval_id"]

    # Step 2: Deactivate the agent in DB
    db = SessionLocal()
    agent = db.query(AgentModel).filter(AgentModel.agent_id == "hitl_test_agent").first()
    agent.is_active = False
    db.commit()
    db.close()

    try:
        # Step 3: Attempt to approve
        appr_res = client.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"justification": "Attempting approval of deactivated agent"},
            headers=headers
        )
        assert appr_res.status_code == 400
        assert "deactivated" in appr_res.text.lower()
        assert not resolved_path.exists(), "Tool must not run when agent is deactivated!"
    finally:
        # Restore agent active status for other tests
        db = SessionLocal()
        agent = db.query(AgentModel).filter(AgentModel.agent_id == "hitl_test_agent").first()
        agent.is_active = True
        db.commit()
        db.close()


def test_approvals_list_filtering(client_and_auth):
    """Listing approvals with status filter returns correct subset."""
    client = client_and_auth["client"]
    analyst_token = client_and_auth["analyst_token"]
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Get all approvals
    res_all = client.get("/api/v1/approvals", headers=headers)
    assert res_all.status_code == 200
    all_items = res_all.json()
    assert len(all_items) > 0

    # Filter by EXECUTED
    res_exec = client.get("/api/v1/approvals?status=EXECUTED", headers=headers)
    assert res_exec.status_code == 200
    exec_items = res_exec.json()
    assert all(item["status"] == "EXECUTED" for item in exec_items)

    # Filter by REJECTED
    res_rej = client.get("/api/v1/approvals?status=REJECTED", headers=headers)
    assert res_rej.status_code == 200
    rej_items = res_rej.json()
    assert all(item["status"] == "REJECTED" for item in rej_items)
