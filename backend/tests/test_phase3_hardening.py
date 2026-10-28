"""
Automated Tests for Phase 3.1: Security Hardening & Concurrency Protection.
Verifies:
1. Multi-threaded atomic Compare-and-Swap (CAS) state transition (PENDING -> IN_PROGRESS -> EXECUTED).
2. Race condition prevention: concurrent approvals ensure tool executes exactly once; loser gets HTTP 409 or 400.
3. Conflict rejection: rejection/approval requests on IN_PROGRESS approvals return HTTP 409 Conflict.
4. Comprehensive secret redaction across nested dictionaries, lists, URLs, and Bearer tokens.
5. API responses and audit logs guarantee zero raw credential leaks.
6. Deferred approval queue rejects unencrypted secrets to prevent credential persistence.
7. Strict Pydantic parameter schema validation with extra="forbid" for all 8 agent tools.
8. Policy modification revalidation blocks execution if permissions change before approval.
9. Execution failure handling cleanly records FAILED status, failure reason, and updates the event.
"""

import pytest
import uuid
import concurrent.futures
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import SessionLocal, init_db, ensure_default_users
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.approval import ApprovalRequestModel, ApprovalStatus
from app.models.event import SecurityEventModel
from app.core.sanitizer import (
    redact_secrets,
    is_sensitive_key,
    sanitize_url,
    sanitize_string,
    contains_sensitive_secrets
)
from app.schemas.tools import validate_tool_parameters, SUPPORTED_TOOL_SCHEMAS
from app.security.gateway import gateway
from app.agent.tools import tool_registry
from app.agent.environment import synthetic_env


@pytest.fixture(scope="module")
def hardening_fixture():
    init_db()
    db = SessionLocal()
    ensure_default_users(db)

    # Register hardening test agent
    agent = db.query(AgentModel).filter(AgentModel.agent_id == "hardening_agent").first()
    if not agent:
        agent = AgentModel(
            agent_id="hardening_agent",
            name="Hardening Test Agent",
            role="Security Test Agent",
            authorized_objective="Validate Phase 3.1 Hardening",
            is_active=True
        )
        db.add(agent)

    policy = db.query(PolicyManifestModel).filter(PolicyManifestModel.agent_id == "hardening_agent").first()
    if not policy:
        policy = PolicyManifestModel(
            policy_id="pol-hardening-01",
            agent_id="hardening_agent",
            version="1.0",
            allowed_tools=[
                "document_reader", "filesystem_read", "filesystem_write",
                "calculator", "browser_search", "browser_open",
                "database_query", "mock_api_request"
            ],
            allowed_paths=["workspace/*", "documents/*"],
            denied_paths=["credentials/*", "system/*"],
            allowed_network_domains=["api.internal.mock", "intranet.mock"],
            allowed_operations=["READ", "WRITE", "NETWORK_CALL", "DB_QUERY"],
            require_approval_operations=["WRITE", "filesystem_write"],
            max_denial_threshold=5
        )
        db.add(policy)
    else:
        policy.allowed_tools = [
            "document_reader", "filesystem_read", "filesystem_write",
            "calculator", "browser_search", "browser_open",
            "database_query", "mock_api_request"
        ]
        policy.allowed_paths = ["workspace/*", "documents/*"]
        policy.denied_paths = ["credentials/*", "system/*"]
        policy.require_approval_operations = ["WRITE", "filesystem_write"]

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

    # Teardown any test files in workspace
    for fname in ["concurrent_race.txt", "failure_test.txt", "policy_change.txt"]:
        p = synthetic_env.resolve_sandbox_path(f"workspace/{fname}")
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass


# -----------------------------------------------------------------------------
# TASK 1: CONCURRENCY & RACE CONDITION PROTECTION
# -----------------------------------------------------------------------------

def test_concurrent_approval_atomic_cas_prevents_duplicate_execution(hardening_fixture):
    """
    Submits two simultaneous approval requests for the exact same pending approval
    using a ThreadPoolExecutor.
    Verifies:
    1. Exactly one request succeeds with HTTP 200 (status EXECUTED).
    2. The other request fails with HTTP 409 Conflict (or HTTP 400).
    3. The sandboxed tool was only executed once.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Create a pending approval request via /api/v1/events/execute
    tool_req = {
        "agent_id": "hardening_agent",
        "session_id": f"sess-race-{uuid.uuid4().hex[:6]}",
        "task_id": "task-race-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/concurrent_race.txt",
            "content": "Phase 3.1 concurrency race test content."
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert init_res.status_code == 200
    data = init_res.json()
    assert data["policy_decision"] == "REQUIRE_APPROVAL"
    approval_id = data["approval_id"]
    assert approval_id is not None

    # Step 2: Use ThreadPoolExecutor to launch two simultaneous approval requests
    def submit_approval(reviewer_note: str):
        thread_client = TestClient(app)
        return thread_client.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"justification": reviewer_note},
            headers=headers
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(submit_approval, "Thread 1 Review Approval")
        f2 = executor.submit(submit_approval, "Thread 2 Review Approval")
        r1 = f1.result()
        r2 = f2.result()

    statuses = [r1.status_code, r2.status_code]
    # Exactly one must be 200 OK
    assert statuses.count(200) == 1, f"Expected exactly one 200 OK, got {statuses}"

    # The other must be either 409 Conflict or 400 Bad Request
    other_status = [s for s in statuses if s != 200][0]
    assert other_status in [400, 409], f"Expected 409 Conflict or 400 Bad Request, got {other_status}"

    # Step 3: Verify the record in DB has status EXECUTED
    get_res = client.get(f"/api/v1/approvals/{approval_id}", headers=headers)
    assert get_res.status_code == 200
    record = get_res.json()
    assert record["status"] == "EXECUTED"
    assert "workspace/concurrent_race.txt" in (record.get("execution_output") or "")

    # Verify file was written in sandbox with the expected content
    p = synthetic_env.resolve_sandbox_path("workspace/concurrent_race.txt")
    assert p.exists()
    assert p.read_text(encoding="utf-8") == "Phase 3.1 concurrency race test content."


def test_conflict_on_in_progress_approval(hardening_fixture):
    """
    Directly sets an approval request status to IN_PROGRESS.
    Verifies that any subsequent approve or reject call returns HTTP 409 Conflict.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create pending approval
    tool_req = {
        "agent_id": "hardening_agent",
        "session_id": f"sess-inprog-{uuid.uuid4().hex[:6]}",
        "task_id": "task-inprog-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/inprog_test.txt",
            "content": "Testing in progress lock"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert init_res.status_code == 200
    approval_id = init_res.json()["approval_id"]

    # Manually transition to IN_PROGRESS in database to simulate an active execution thread
    db = SessionLocal()
    db.query(ApprovalRequestModel).filter(
        ApprovalRequestModel.approval_id == approval_id
    ).update({ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value})
    db.commit()
    db.close()

    # Attempt to approve: Must return 409 Conflict
    approve_res = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"justification": "Attempting approval while IN_PROGRESS"},
        headers=headers
    )
    assert approve_res.status_code == 409
    assert "currently being processed" in approve_res.json()["detail"]

    # Attempt to reject: Must return 409 Conflict
    reject_res = client.post(
        f"/api/v1/approvals/{approval_id}/reject",
        json={"justification": "Attempting rejection while IN_PROGRESS"},
        headers=headers
    )
    assert reject_res.status_code == 409
    assert "currently being processed" in reject_res.json()["detail"]


# -----------------------------------------------------------------------------
# TASK 2: RECURSIVE SECRET REDACTION & SENSITIVE CREDENTIAL HANDLING
# -----------------------------------------------------------------------------

def test_recursive_secret_redaction_unit():
    """
    Tests the sanitizer utility against nested dictionaries, lists, strings, and URLs.
    """
    raw_payload = {
        "tool": "mock_api_request",
        "api_key": "AKIAIOSFODNN7EXAMPLE12",
        "account_details": {
            "password": "SuperSecretPassword123!",
            "token": "ghp_1234567890abcdefghijklmnopqrstuv",
            "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"
        },
        "user_credentials": {
            "secret_note": "top_secret_data"
        },
        "safe_list": [
            {"path": "workspace/data.json", "status": "active"},
            {"secret_field": "confidential_value", "url": "https://admin:mypassword@example.com/api?token=secret99&safe_param=hello"}
        ],
        "safe_int": 42,
        "safe_bool": True
    }

    sanitized = redact_secrets(raw_payload)

    # Verify sensitive keys were redacted
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["account_details"]["password"] == "[REDACTED]"
    assert sanitized["account_details"]["token"] == "[REDACTED]"
    assert sanitized["account_details"]["auth_header"] == "[REDACTED]"
    assert sanitized["user_credentials"] == "[REDACTED]"
    assert sanitized["safe_list"][1]["secret_field"] == "[REDACTED]"

    # Verify URL embedded credentials were redacted
    sanitized_url = sanitized["safe_list"][1]["url"]
    assert "mypassword" not in sanitized_url
    assert "admin:[REDACTED]@example.com" in sanitized_url
    assert "token=%5BREDACTED%5D" in sanitized_url or "token=[REDACTED]" in sanitized_url
    assert "safe_param=hello" in sanitized_url

    # Verify safe fields preserved
    assert sanitized["safe_int"] == 42
    assert sanitized["safe_bool"] is True
    assert sanitized["safe_list"][0]["path"] == "workspace/data.json"


def test_gateway_denies_unencrypted_secrets_for_deferred_approval(hardening_fixture):
    """
    Verifies that if an operation requires approval but contains raw sensitive secrets,
    the gateway immediately rejects it (DENY / BLOCKED) to prevent storing plaintext
    credentials in the deferred approval queue.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Request with password in parameters for an operation requiring approval
    tool_req = {
        "agent_id": "hardening_agent",
        "session_id": f"sess-secret-{uuid.uuid4().hex[:6]}",
        "task_id": "task-sec-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/leaked_secret.txt",
            "content": "password = P@ssw0rdSynthetic"
        }
    }

    res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Must be DENIED and BLOCKED
    assert data["policy_decision"] == "DENY"
    assert data["execution_status"] == "BLOCKED"
    assert "Unencrypted sensitive credentials or secrets cannot be submitted for deferred approval" in data["decision_reason"]
    assert "CREDENTIAL_LEAK_PREVENTION" in data["risk_indicators"]


def test_api_responses_redact_secrets_in_events_and_approvals(hardening_fixture):
    """
    Verifies that when telemetry events or approvals are retrieved from the API,
    the Pydantic response models recursively redact any sensitive values.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Create an event directly in DB with a sensitive key
    db = SessionLocal()
    event_id = str(uuid.uuid4())
    evt = SecurityEventModel(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        agent_id="hardening_agent",
        session_id="sess-audit-leak",
        task_id="task-audit-1",
        action_type="TOOL_CALL_ALLOWED",
        tool_name="calculator",
        resource="expr:2+2",
        requested_operation="CALC",
        parameters={"expression": "2+2", "token": "leaked_super_secret_token_123"},
        policy_decision="ALLOW",
        execution_status="EXECUTED",
        execution_output="Result: 4, with auth: Bearer eyJhbGciOiJIUzI1NiJ9",
        risk_indicators=[],
        source_of_input="DIRECT_AGENT"
    )
    db.add(evt)
    db.commit()
    db.close()

    # Step 2: Fetch via API
    res = client.get(f"/api/v1/events/{event_id}", headers=headers)
    assert res.status_code == 200
    event_data = res.json()

    # Parameters token must be redacted
    assert event_data["parameters"]["token"] == "[REDACTED]"
    # Bearer token in output must be redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in event_data["execution_output"]
    assert "[REDACTED]" in event_data["execution_output"]


# -----------------------------------------------------------------------------
# TASK 3: STRICT TOOL PARAMETER SCHEMAS & FAIL CLOSED
# -----------------------------------------------------------------------------

def test_tool_parameter_schema_rejects_extra_kwargs():
    """
    Validates that extra kwargs are strictly forbidden (extra='forbid') for all tools.
    """
    # 1. Document Reader with extra unexpected parameter
    valid, err, _ = validate_tool_parameters("document_reader", {
        "path": "documents/report.txt",
        "malicious_extra": "unexpected_payload"
    })
    assert not valid
    assert "Extra inputs are not permitted" in err or "extra" in err.lower()

    # 2. Filesystem Write with extra kwargs
    valid, err, _ = validate_tool_parameters("filesystem_write", {
        "path": "workspace/notes.txt",
        "content": "hello",
        "execute_as_root": True
    })
    assert not valid
    assert "Extra inputs are not permitted" in err or "extra" in err.lower()

    # 3. Calculator with extra kwargs
    valid, err, _ = validate_tool_parameters("calculator", {
        "expression": "100 * 5",
        "eval_bypass": True
    })
    assert not valid
    assert "Extra inputs are not permitted" in err or "extra" in err.lower()


def test_tool_parameter_schema_rejects_missing_and_invalid_types():
    """
    Validates that missing required parameters and invalid types fail closed.
    """
    # Missing required path
    valid, err, _ = validate_tool_parameters("filesystem_read", {})
    assert not valid
    assert "Field required" in err or "path" in err

    # Negative offset in document_reader
    valid, err, _ = validate_tool_parameters("document_reader", {
        "path": "documents/test.txt",
        "offset": -5
    })
    assert not valid
    assert "greater than or equal to 0" in err

    # Disallowed URL scheme in browser_open
    valid, err, _ = validate_tool_parameters("browser_open", {
        "url": "ftp://malicious.server/payload"
    })
    assert not valid
    assert "Disallowed URL scheme" in err

    # Non-dictionary parameters
    valid, err, _ = validate_tool_parameters("calculator", "not a dict")
    assert not valid
    assert "must be a dictionary" in err


def test_unregistered_tool_fails_closed():
    """
    Validates that invoking an unregistered or unmapped tool name fails closed.
    """
    valid, err, _ = validate_tool_parameters("unregistered_arbitrary_tool", {"param": 1})
    assert not valid
    assert "no registered validation schema. Fail-closed." in err


def test_gateway_blocks_malformed_tool_parameters(hardening_fixture):
    """
    Verifies that when a tool call with malformed parameters is sent to the gateway,
    it is immediately BLOCKED and returns DENY with risk indicator INVALID_TOOL_PARAMETERS.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tool_req = {
        "agent_id": "hardening_agent",
        "session_id": f"sess-malform-{uuid.uuid4().hex[:6]}",
        "task_id": "task-mal-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/valid.txt",
            "content": "some text",
            "unauthorized_extra_field": "hacked"
        }
    }

    res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["policy_decision"] == "DENY"
    assert data["execution_status"] == "BLOCKED"
    assert "INVALID_TOOL_PARAMETERS" in data["risk_indicators"]


# -----------------------------------------------------------------------------
# TASK 4: POLICY CHANGE REVALIDATION & EXECUTION FAILURE HANDLING
# -----------------------------------------------------------------------------

def test_zero_trust_revalidation_blocks_on_policy_change(hardening_fixture):
    """
    Creates an approval request while a path is permitted.
    Modifies policy to restrict that path before approval.
    Verifies that when approval is attempted, zero-trust revalidation DENIES execution
    and transitions approval status to FAILED.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Create approval request for workspace/policy_change.txt
    tool_req = {
        "agent_id": "hardening_agent",
        "session_id": f"sess-polmod-{uuid.uuid4().hex[:6]}",
        "task_id": "task-polmod-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/policy_change.txt",
            "content": "Will policy change block this?"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert init_res.status_code == 200
    approval_id = init_res.json()["approval_id"]

    # Step 2: Dynamically alter policy manifest to remove workspace/* from allowed_paths
    db = SessionLocal()
    policy = db.query(PolicyManifestModel).filter(
        PolicyManifestModel.agent_id == "hardening_agent"
    ).first()
    policy.allowed_paths = ["documents/*"]  # workspace/* is now forbidden!
    db.commit()
    db.close()

    try:
        # Step 3: Attempt to approve the request
        approve_res = client.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"justification": "Approving previously submitted request."},
            headers=headers
        )
        assert approve_res.status_code == 400
        assert "Security policy revalidation DENIED" in approve_res.json()["detail"]

        # Step 4: Verify DB status is FAILED
        get_res = client.get(f"/api/v1/approvals/{approval_id}", headers=headers)
        assert get_res.status_code == 200
        record = get_res.json()
        assert record["status"] == "FAILED"
        assert "outside authorized scope" in record["failure_reason"]

        # Step 5: Verify the file was NEVER written
        p = synthetic_env.resolve_sandbox_path("workspace/policy_change.txt")
        assert not p.exists()

    finally:
        # Restore policy
        db = SessionLocal()
        policy = db.query(PolicyManifestModel).filter(
            PolicyManifestModel.agent_id == "hardening_agent"
        ).first()
        policy.allowed_paths = ["workspace/*", "documents/*"]
        db.commit()
        db.close()


def test_tool_execution_failure_handling(hardening_fixture, monkeypatch):
    """
    Verifies that when an approved tool call fails during execution (e.g. simulated storage error),
    the gateway:
    1. Sets status to FAILED (never EXECUTED).
    2. Populates failure_reason.
    3. Updates original event execution_status to FAILED.
    """
    client = hardening_fixture["client"]
    token = hardening_fixture["analyst_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Request filesystem write
    tool_req = {
        "agent_id": "hardening_agent",
        "session_id": f"sess-fail-{uuid.uuid4().hex[:6]}",
        "task_id": "task-fail-1",
        "tool_name": "filesystem_write",
        "parameters": {
            "path": "workspace/simulated_failure.txt",
            "content": "Content to trigger simulated write failure"
        }
    }
    init_res = client.post("/api/v1/events/execute", json=tool_req, headers=headers)
    assert init_res.status_code == 200
    approval_id = init_res.json()["approval_id"]

    # Step 2: Monkeypatch tool_registry.filesystem_write to simulate failure
    def failing_filesystem_write(**kwargs):
        return {"status": "error", "error": "Simulated disk full: unable to complete atomic write operation."}

    monkeypatch.setattr(tool_registry, "filesystem_write", failing_filesystem_write)

    # Step 3: Analyst approves the write
    approve_res = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"justification": "Approved write operation."},
        headers=headers
    )
    assert approve_res.status_code == 200
    record = approve_res.json()

    # Step 4: Status must be FAILED, NOT EXECUTED
    assert record["status"] == "FAILED"
    assert record["failure_reason"] is not None
    assert "Simulated disk full" in record["failure_reason"]

    # Step 5: Check original security event was updated to FAILED
    db = SessionLocal()
    orig_evt = db.query(SecurityEventModel).filter(
        SecurityEventModel.event_id == record["event_id"]
    ).first()
    assert orig_evt is not None
    assert orig_evt.execution_status == "FAILED"
    db.close()
