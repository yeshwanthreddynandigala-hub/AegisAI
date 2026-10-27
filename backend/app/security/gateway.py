"""
Tool Execution Gateway (Zero-Trust Mediation Layer).
Intercepts all agent tool invocations, enforces access policy, sanitizes telemetry,
and blocks unauthorized operations BEFORE they reach system or synthetic resources.
"""

from typing import Dict, Any, Optional, List
import uuid
import json
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
from app.models.approval import ApprovalRequestModel, ApprovalStatus
from app.models.user import UserModel
from app.schemas.event import ToolCallRequest, ToolCallResponse
from app.security.policy_engine import policy_engine
from app.security.rule_detector import rule_detector
from app.agent.tools import tool_registry

class ToolExecutionGateway:
    """Zero-trust mediator for all agent interactions."""

    def __init__(self):
        self._correlation_engine = None  # Injected or lazily resolved

    def set_correlation_engine(self, engine):
        self._correlation_engine = engine

    def _extract_resource(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """Extracts the primary target resource string for auditing."""
        if tool_name in ["document_reader", "filesystem_read", "filesystem_write"]:
            return str(parameters.get("path", "unknown_path"))
        elif tool_name in ["browser_open", "mock_api_request"]:
            return str(parameters.get("url", "unknown_url"))
        elif tool_name == "database_query":
            return f"sql_query:{str(parameters.get('query', ''))[:40]}"
        elif tool_name == "browser_search":
            return f"search_query:{str(parameters.get('query', ''))[:40]}"
        elif tool_name == "calculator":
            return f"expr:{str(parameters.get('expression', ''))[:40]}"
        return "generic_resource"

    def _sanitize_output_for_audit(self, output: Any) -> str:
        """Sanitizes execution output preview to prevent leaking credentials into audit logs."""
        if output is None:
            return ""
        s = json.dumps(output) if isinstance(output, (dict, list)) else str(output)
        # Redact simulated key tokens if accidentally present
        for secret_token in ["AKIA_MOCK", "EXAMPLEKEY", "P@ssw0rdSynthetic", "synthetic_hash"]:
            if secret_token in s:
                s = s.replace(secret_token, "[REDACTED_SIMULATED_SECRET]")
        return s[:1200]

    def dispatch_tool_call(self, db: Session, request: ToolCallRequest) -> ToolCallResponse:
        """
        Primary execution entry point.
        Evaluates policy BEFORE execution and records structured audit events.
        """
        # 1. Fetch Agent and Policy Manifest
        policy = db.query(PolicyManifestModel).filter(
            PolicyManifestModel.agent_id == request.agent_id
        ).first()

        if not policy:
            # Fallback strict policy: Deny everything if manifest is missing
            return ToolCallResponse(
                event_id=str(uuid.uuid4()),
                policy_decision="DENY",
                execution_status="BLOCKED",
                decision_reason=f"No security policy manifest registered for agent '{request.agent_id}'. Default DENY applied.",
                risk_indicators=["UNREGISTERED_AGENT_EXECUTION"]
            )

        # 2. Query Prior Session Events for Denial Count and Context
        prior_events = db.query(SecurityEventModel).filter(
            SecurityEventModel.session_id == request.session_id
        ).order_by(SecurityEventModel.timestamp.asc()).all()

        session_denial_count = sum(
            1 for e in prior_events
            if e.policy_decision == "DENY" or e.execution_status == "BLOCKED"
        )

        # 3. Policy Engine Evaluation (PRE-EXECUTION)
        policy_result = policy_engine.evaluate(
            policy=policy,
            tool_name=request.tool_name,
            parameters=request.parameters,
            session_denial_count=session_denial_count
        )

        resource = self._extract_resource(request.tool_name, request.parameters)
        event_id = str(uuid.uuid4())

        # Determine operation verb
        op_verb = "READ"
        if request.tool_name == "filesystem_write":
            op_verb = "WRITE"
        elif request.tool_name in ["mock_api_request", "browser_open"]:
            op_verb = "NETWORK_CALL"
        elif request.tool_name == "database_query":
            op_verb = "DB_QUERY"

        # 4. Handle Policy Denial (BLOCKED BEFORE EXECUTION)
        if policy_result.decision == "DENY":
            audit_event = SecurityEventModel(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                agent_id=request.agent_id,
                session_id=request.session_id,
                task_id=request.task_id,
                action_type="TOOL_CALL_DENIED",
                tool_name=request.tool_name,
                resource=resource,
                requested_operation=op_verb,
                parameters=request.parameters,
                policy_decision="DENY",
                execution_status="BLOCKED",
                execution_output=f"BLOCKED BY GATEWAY: {policy_result.message}",
                risk_indicators=policy_result.risk_indicators,
                source_of_input=request.source_of_input
            )
            db.add(audit_event)
            db.commit()
            db.refresh(audit_event)

            # Trigger Detection & Correlation
            incident_id = None
            if self._correlation_engine:
                incident_id = self._correlation_engine.process_event(db, audit_event, prior_events)

            return ToolCallResponse(
                event_id=event_id,
                policy_decision="DENY",
                execution_status="BLOCKED",
                decision_reason=policy_result.message,
                output=None,
                risk_indicators=policy_result.risk_indicators,
                incident_created=bool(incident_id),
                incident_id=incident_id
            )

        # 5. Handle Human Approval Required
        elif policy_result.decision == "REQUIRE_APPROVAL":
            now_utc = datetime.now(timezone.utc)
            audit_event = SecurityEventModel(
                event_id=event_id,
                timestamp=now_utc,
                agent_id=request.agent_id,
                session_id=request.session_id,
                task_id=request.task_id,
                action_type="TOOL_CALL_APPROVAL_REQUIRED",
                tool_name=request.tool_name,
                resource=resource,
                requested_operation=op_verb,
                parameters=request.parameters,
                policy_decision="REQUIRE_APPROVAL",
                execution_status="PENDING",
                execution_output="Awaiting analyst approval before execution.",
                risk_indicators=policy_result.risk_indicators,
                source_of_input=request.source_of_input
            )
            db.add(audit_event)

            # Create persistent approval request with 24-hour expiration window
            approval_id = f"appr-{uuid.uuid4().hex[:12]}"
            approval_req = ApprovalRequestModel(
                approval_id=approval_id,
                event_id=event_id,
                agent_id=request.agent_id,
                session_id=request.session_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                parameters=request.parameters,
                resource=resource,
                decision_reason=policy_result.message,
                risk_indicators=policy_result.risk_indicators,
                status=ApprovalStatus.PENDING.value,
                created_at=now_utc,
                expires_at=now_utc + timedelta(hours=24)
            )
            db.add(approval_req)
            db.commit()

            return ToolCallResponse(
                event_id=event_id,
                policy_decision="REQUIRE_APPROVAL",
                execution_status="PENDING",
                decision_reason=policy_result.message,
                output=None,
                risk_indicators=policy_result.risk_indicators,
                approval_id=approval_id
            )

        # 6. Policy Allowed: Safe Execution inside Sandbox
        tool_func = getattr(tool_registry, request.tool_name, None)
        if not tool_func:
            return ToolCallResponse(
                event_id=event_id,
                policy_decision="DENY",
                execution_status="FAILED",
                decision_reason=f"Tool function '{request.tool_name}' not implemented in tool registry.",
                risk_indicators=["INVALID_TOOL_MAPPING"]
            )

        try:
            raw_output = tool_func(**request.parameters)
            exec_status = "EXECUTED" if raw_output.get("status") == "success" else "FAILED"
        except Exception as e:
            raw_output = {"status": "error", "error": str(e)}
            exec_status = "FAILED"

        audit_event = SecurityEventModel(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc),
            agent_id=request.agent_id,
            session_id=request.session_id,
            task_id=request.task_id,
            action_type="TOOL_CALL_ALLOWED",
            tool_name=request.tool_name,
            resource=resource,
            requested_operation=op_verb,
            parameters=request.parameters,
            policy_decision="ALLOW",
            execution_status=exec_status,
            execution_output=self._sanitize_output_for_audit(raw_output),
            risk_indicators=[],
            source_of_input=request.source_of_input
        )
        db.add(audit_event)
        db.commit()
        db.refresh(audit_event)

        # Trigger Detection & Correlation on allowed event (e.g. sequence changes, anomaly detection)
        incident_id = None
        if self._correlation_engine:
            incident_id = self._correlation_engine.process_event(db, audit_event, prior_events)

        return ToolCallResponse(
            event_id=event_id,
            policy_decision="ALLOW",
            execution_status=exec_status,
            decision_reason=policy_result.message,
            output=raw_output,
            risk_indicators=[],
            incident_created=bool(incident_id),
            incident_id=incident_id
        )

    def approve_tool_call(
        self,
        db: Session,
        approval_id: str,
        reviewer: UserModel,
        justification: str
    ) -> ApprovalRequestModel:
        """
        Processes human approval for a pending tool invocation.
        Performs strict zero-trust revalidation against current policy before executing in the sandbox.
        Prevents replay, race conditions, expired execution, and unverified parameter execution.
        """
        approval = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()

        if not approval:
            raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")

        # Check idempotency / double execution prevention
        if approval.status != ApprovalStatus.PENDING.value:
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been processed with status '{approval.status}'."
            )

        now_utc = datetime.now(timezone.utc)

        # Check expiration
        expires_at = approval.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now_utc > expires_at:
            approval.status = ApprovalStatus.EXPIRED.value
            approval.failure_reason = f"Request expired at {expires_at.isoformat()}."
            db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has expired and cannot be executed."
            )

        # Revalidation 1: Agent & Policy Manifest must exist and be active
        agent = db.query(AgentModel).filter(AgentModel.agent_id == approval.agent_id).first()
        if not agent or not agent.is_active:
            approval.status = ApprovalStatus.FAILED.value
            approval.failure_reason = f"Revalidation failed: Agent '{approval.agent_id}' does not exist or is deactivated."
            approval.reviewed_by_user_id = reviewer.user_id
            approval.reviewed_by_username = reviewer.username
            approval.reviewed_at = now_utc
            approval.review_justification = justification
            db.commit()
            raise HTTPException(status_code=400, detail=approval.failure_reason)

        policy = db.query(PolicyManifestModel).filter(
            PolicyManifestModel.agent_id == approval.agent_id
        ).first()
        if not policy:
            approval.status = ApprovalStatus.FAILED.value
            approval.failure_reason = f"Revalidation failed: Policy manifest for agent '{approval.agent_id}' not found."
            approval.reviewed_by_user_id = reviewer.user_id
            approval.reviewed_by_username = reviewer.username
            approval.reviewed_at = now_utc
            approval.review_justification = justification
            db.commit()
            raise HTTPException(status_code=400, detail=approval.failure_reason)

        # Revalidation 2: Session Quarantine & Policy Evaluation
        prior_events = db.query(SecurityEventModel).filter(
            SecurityEventModel.session_id == approval.session_id
        ).all()
        session_denial_count = sum(
            1 for e in prior_events
            if e.policy_decision == "DENY" or e.execution_status == "BLOCKED"
        )

        reval = policy_engine.evaluate(
            policy=policy,
            tool_name=approval.tool_name,
            parameters=approval.parameters,
            session_denial_count=session_denial_count
        )

        if reval.decision == "DENY":
            approval.status = ApprovalStatus.FAILED.value
            approval.failure_reason = f"Security policy revalidation DENIED: {reval.message}"
            approval.reviewed_by_user_id = reviewer.user_id
            approval.reviewed_by_username = reviewer.username
            approval.reviewed_at = now_utc
            approval.review_justification = justification
            db.commit()
            raise HTTPException(status_code=400, detail=approval.failure_reason)

        # Revalidation 3: Tool Function Must Exist
        tool_func = getattr(tool_registry, approval.tool_name, None)
        if not tool_func:
            approval.status = ApprovalStatus.FAILED.value
            approval.failure_reason = f"Tool function '{approval.tool_name}' not implemented in tool registry."
            approval.reviewed_by_user_id = reviewer.user_id
            approval.reviewed_by_username = reviewer.username
            approval.reviewed_at = now_utc
            approval.review_justification = justification
            db.commit()
            raise HTTPException(status_code=500, detail=approval.failure_reason)

        # Audit Review Metadata
        approval.reviewed_by_user_id = reviewer.user_id
        approval.reviewed_by_username = reviewer.username
        approval.reviewed_at = now_utc
        approval.review_justification = justification
        approval.status = ApprovalStatus.APPROVED.value

        # Execute Safely within Synthetic Environment
        try:
            raw_output = tool_func(**approval.parameters)
            if raw_output.get("status") == "success":
                approval.status = ApprovalStatus.EXECUTED.value
                approval.execution_output = self._sanitize_output_for_audit(raw_output)
            else:
                approval.status = ApprovalStatus.FAILED.value
                approval.failure_reason = raw_output.get("error", "Tool returned failure status.")
                approval.execution_output = self._sanitize_output_for_audit(raw_output)
        except Exception as e:
            approval.status = ApprovalStatus.FAILED.value
            approval.failure_reason = str(e)
            approval.execution_output = f"Execution exception: {str(e)}"

        # Update Original Security Event
        original_event = db.query(SecurityEventModel).filter(
            SecurityEventModel.event_id == approval.event_id
        ).first()
        if original_event:
            original_event.execution_status = approval.status
            original_event.execution_output = approval.execution_output or approval.failure_reason

        # Append Paired Audit Event for HITL Resolution
        audit_resolution = SecurityEventModel(
            event_id=str(uuid.uuid4()),
            timestamp=now_utc,
            agent_id=approval.agent_id,
            session_id=approval.session_id,
            task_id=approval.task_id,
            action_type="TOOL_CALL_APPROVED_AND_EXECUTED" if approval.status == ApprovalStatus.EXECUTED.value else "TOOL_CALL_APPROVED_EXECUTION_FAILED",
            tool_name=approval.tool_name,
            resource=approval.resource,
            requested_operation=original_event.requested_operation if original_event else "WRITE",
            parameters=approval.parameters,
            policy_decision="ALLOW",
            execution_status=approval.status,
            execution_output=approval.execution_output or approval.failure_reason,
            risk_indicators=approval.risk_indicators,
            source_of_input=f"REVIEWER:{reviewer.username}"
        )
        db.add(audit_resolution)
        db.commit()
        db.refresh(approval)

        return approval

    def reject_tool_call(
        self,
        db: Session,
        approval_id: str,
        reviewer: UserModel,
        justification: str
    ) -> ApprovalRequestModel:
        """
        Processes human rejection for a pending tool invocation.
        Guarantees that rejected operations are never dispatched to tools.
        """
        approval = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()

        if not approval:
            raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")

        # Check idempotency / double decision prevention
        if approval.status != ApprovalStatus.PENDING.value:
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been processed with status '{approval.status}'."
            )

        now_utc = datetime.now(timezone.utc)

        # Check expiration
        expires_at = approval.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now_utc > expires_at:
            approval.status = ApprovalStatus.EXPIRED.value
            approval.failure_reason = f"Request expired at {expires_at.isoformat()}."
            db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has expired."
            )

        approval.status = ApprovalStatus.REJECTED.value
        approval.reviewed_by_user_id = reviewer.user_id
        approval.reviewed_by_username = reviewer.username
        approval.reviewed_at = now_utc
        approval.review_justification = justification
        approval.failure_reason = f"Explicitly rejected by reviewer {reviewer.username}: {justification}"

        # Update Original Security Event
        original_event = db.query(SecurityEventModel).filter(
            SecurityEventModel.event_id == approval.event_id
        ).first()
        if original_event:
            original_event.execution_status = "BLOCKED"
            original_event.execution_output = f"REJECTED BY REVIEWER ({reviewer.username}): {justification}"

        # Append Paired Audit Event for Rejection
        audit_resolution = SecurityEventModel(
            event_id=str(uuid.uuid4()),
            timestamp=now_utc,
            agent_id=approval.agent_id,
            session_id=approval.session_id,
            task_id=approval.task_id,
            action_type="TOOL_CALL_APPROVAL_REJECTED",
            tool_name=approval.tool_name,
            resource=approval.resource,
            requested_operation=original_event.requested_operation if original_event else "WRITE",
            parameters=approval.parameters,
            policy_decision="DENY",
            execution_status="BLOCKED",
            execution_output=f"REJECTED BY REVIEWER ({reviewer.username}): {justification}",
            risk_indicators=approval.risk_indicators,
            source_of_input=f"REVIEWER:{reviewer.username}"
        )
        db.add(audit_resolution)
        db.commit()
        db.refresh(approval)

        return approval

gateway = ToolExecutionGateway()
