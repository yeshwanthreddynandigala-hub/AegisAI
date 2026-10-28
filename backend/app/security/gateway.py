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
from app.core.config import settings
from app.core.sanitizer import redact_secrets, contains_sensitive_secrets
from app.schemas.tools import validate_tool_parameters


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
        sanitized = redact_secrets(output)
        s = json.dumps(sanitized) if isinstance(sanitized, (dict, list)) else str(sanitized)
        return s[:1200]

    def dispatch_tool_call(self, db: Session, request: ToolCallRequest) -> ToolCallResponse:
        """
        Primary execution entry point.
        Evaluates parameter schema, policy, and secret leaks BEFORE execution,
        and records structured audit events.
        """
        # 0. Strict Parameter Schema Validation (Fail Closed)
        is_valid, err_msg, validated_params = validate_tool_parameters(request.tool_name, request.parameters)
        if not is_valid:
            event_id = str(uuid.uuid4())
            resource = self._extract_resource(
                request.tool_name,
                request.parameters if isinstance(request.parameters, dict) else {}
            )
            audit_event = SecurityEventModel(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                agent_id=request.agent_id,
                session_id=request.session_id,
                task_id=request.task_id,
                action_type="TOOL_CALL_DENIED",
                tool_name=request.tool_name,
                resource=resource,
                requested_operation="EXECUTE",
                parameters=redact_secrets(request.parameters) if isinstance(request.parameters, dict) else {},
                policy_decision="DENY",
                execution_status="BLOCKED",
                execution_output=f"BLOCKED BY GATEWAY: {err_msg}",
                risk_indicators=["INVALID_TOOL_PARAMETERS"],
                source_of_input=request.source_of_input
            )
            db.add(audit_event)
            db.commit()
            db.refresh(audit_event)

            return ToolCallResponse(
                event_id=event_id,
                policy_decision="DENY",
                execution_status="BLOCKED",
                decision_reason=err_msg or "Invalid tool parameters.",
                output=None,
                risk_indicators=["INVALID_TOOL_PARAMETERS"]
            )

        request_params = validated_params

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
            parameters=request_params,
            session_denial_count=session_denial_count
        )

        resource = self._extract_resource(request.tool_name, request_params)
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
                parameters=redact_secrets(request_params),
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
            # Guard against persisting unencrypted credentials to deferred approval queue
            if contains_sensitive_secrets(request_params):
                deny_reason = "Unencrypted sensitive credentials or secrets cannot be submitted for deferred approval."
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
                    parameters=redact_secrets(request_params),
                    policy_decision="DENY",
                    execution_status="BLOCKED",
                    execution_output=f"BLOCKED BY GATEWAY: {deny_reason}",
                    risk_indicators=["CREDENTIAL_LEAK_PREVENTION", "SENSITIVE_SECRET_EXPOSURE"],
                    source_of_input=request.source_of_input
                )
                db.add(audit_event)
                db.commit()
                db.refresh(audit_event)

                return ToolCallResponse(
                    event_id=event_id,
                    policy_decision="DENY",
                    execution_status="BLOCKED",
                    decision_reason=deny_reason,
                    output=None,
                    risk_indicators=["CREDENTIAL_LEAK_PREVENTION", "SENSITIVE_SECRET_EXPOSURE"]
                )

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
                parameters=redact_secrets(request_params),
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
                parameters=request_params,
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
            raw_output = tool_func(**request_params)
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
            parameters=redact_secrets(request_params),
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
        Performs atomic CAS state transition (PENDING -> IN_PROGRESS) to prevent race conditions.
        Performs strict zero-trust revalidation against current policy before executing in the sandbox.
        Tool execution is performed OUTSIDE the database transaction.
        Sets status to EXECUTED only upon confirmed execution success, or FAILED on error.
        """
        approval = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()

        if not approval:
            raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")

        now_utc = datetime.now(timezone.utc)

        # Check if another reviewer/thread is actively executing this request
        if approval.status == ApprovalStatus.IN_PROGRESS.value:
            is_stale, lease_age = self._is_approval_lease_expired(approval, now_utc)
            if is_stale:
                self.recover_stale_approvals(db)
                raise HTTPException(
                    status_code=400,
                    detail=f"Approval request '{approval_id}' timed out while in progress ({lease_age:.1f}s ago) and has been marked FAILED. Operation outcome is uncertain and will not be automatically retried."
                )
            raise HTTPException(
                status_code=409,
                detail=f"Approval request '{approval_id}' is currently being processed by another reviewer or thread."
            )

        # Check idempotency / double execution prevention
        if approval.status != ApprovalStatus.PENDING.value:
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been processed with status '{approval.status}'."
            )

        # Check expiration
        expires_at = approval.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now_utc > expires_at:
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id,
                ApprovalRequestModel.status == ApprovalStatus.PENDING.value
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.EXPIRED.value,
                ApprovalRequestModel.failure_reason: f"Request expired at {expires_at.isoformat()}."
            })
            db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has expired and cannot be executed."
            )

        # Atomic Compare-and-Swap: PENDING -> IN_PROGRESS
        rows_affected = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id,
            ApprovalRequestModel.status == ApprovalStatus.PENDING.value
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.IN_PROGRESS.value,
            ApprovalRequestModel.reviewed_by_user_id: reviewer.user_id,
            ApprovalRequestModel.reviewed_by_username: reviewer.username,
            ApprovalRequestModel.reviewed_at: now_utc,
            ApprovalRequestModel.execution_started_at: now_utc,
            ApprovalRequestModel.review_justification: justification
        })
        db.commit()

        if rows_affected == 0:
            current = db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).first()
            if current and current.status == ApprovalStatus.IN_PROGRESS.value:
                raise HTTPException(
                    status_code=409,
                    detail=f"Approval request '{approval_id}' is currently being processed by another reviewer or thread."
                )
            current_status = current.status if current else "UNKNOWN"
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been processed with status '{current_status}'."
            )

        # Revalidation 1: Tool Parameters Schema
        is_valid, err_msg, validated_params = validate_tool_parameters(approval.tool_name, approval.parameters)
        if not is_valid:
            fail_msg = f"Parameter revalidation failed: {err_msg}"
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.FAILED.value,
                ApprovalRequestModel.failure_reason: fail_msg
            })
            db.commit()
            raise HTTPException(status_code=400, detail=fail_msg)

        # Revalidation 2: Agent & Policy Manifest must exist and be active
        agent = db.query(AgentModel).filter(AgentModel.agent_id == approval.agent_id).first()
        if not agent or not agent.is_active:
            fail_msg = f"Revalidation failed: Agent '{approval.agent_id}' does not exist or is deactivated."
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.FAILED.value,
                ApprovalRequestModel.failure_reason: fail_msg
            })
            db.commit()
            raise HTTPException(status_code=400, detail=fail_msg)

        policy = db.query(PolicyManifestModel).filter(
            PolicyManifestModel.agent_id == approval.agent_id
        ).first()
        if not policy:
            fail_msg = f"Revalidation failed: Policy manifest for agent '{approval.agent_id}' not found."
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.FAILED.value,
                ApprovalRequestModel.failure_reason: fail_msg
            })
            db.commit()
            raise HTTPException(status_code=400, detail=fail_msg)

        # Revalidation 3: Session Quarantine & Policy Evaluation
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
            parameters=validated_params,
            session_denial_count=session_denial_count
        )

        if reval.decision == "DENY":
            fail_msg = f"Security policy revalidation DENIED: {reval.message}"
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.FAILED.value,
                ApprovalRequestModel.failure_reason: fail_msg
            })
            db.commit()
            raise HTTPException(status_code=400, detail=fail_msg)

        # Revalidation 4: Tool Function Must Exist
        tool_func = getattr(tool_registry, approval.tool_name, None)
        if not tool_func:
            fail_msg = f"Tool function '{approval.tool_name}' not implemented in tool registry."
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.FAILED.value,
                ApprovalRequestModel.failure_reason: fail_msg
            })
            db.commit()
            raise HTTPException(status_code=500, detail=fail_msg)

        # Execute Safely within Synthetic Environment (OUTSIDE DB TRANSACTION)
        exec_success = False
        try:
            raw_output = tool_func(**validated_params)
            if isinstance(raw_output, dict) and raw_output.get("status") == "success":
                exec_success = True
                final_status = ApprovalStatus.EXECUTED.value
                execution_output_str = self._sanitize_output_for_audit(raw_output)
                fail_reason = None
            else:
                exec_success = False
                final_status = ApprovalStatus.FAILED.value
                fail_reason = raw_output.get("error", "Tool returned failure status.") if isinstance(raw_output, dict) else "Tool returned failure."
                execution_output_str = self._sanitize_output_for_audit(raw_output)
        except Exception as e:
            exec_success = False
            final_status = ApprovalStatus.FAILED.value
            fail_reason = str(e)
            execution_output_str = f"Execution exception: {str(e)}"

        # Final Database Updates - Atomic transition from IN_PROGRESS
        rows_updated = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id,
            ApprovalRequestModel.status == ApprovalStatus.IN_PROGRESS.value
        ).update({
            ApprovalRequestModel.status: final_status,
            ApprovalRequestModel.execution_output: execution_output_str,
            ApprovalRequestModel.failure_reason: fail_reason
        })
        db.commit()

        if rows_updated == 0:
            # Stale recovery or terminal transition occurred while executing tool
            # Do NOT overwrite terminal status!
            approval = db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).first()
            return approval

        # Update Original Security Event
        original_event = db.query(SecurityEventModel).filter(
            SecurityEventModel.event_id == approval.event_id
        ).first()
        if original_event:
            original_event.execution_status = final_status
            original_event.execution_output = execution_output_str or fail_reason

        # Append Paired Audit Event for HITL Resolution
        audit_resolution = SecurityEventModel(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            agent_id=approval.agent_id,
            session_id=approval.session_id,
            task_id=approval.task_id,
            action_type="TOOL_CALL_APPROVED_AND_EXECUTED" if exec_success else "TOOL_CALL_APPROVED_EXECUTION_FAILED",
            tool_name=approval.tool_name,
            resource=approval.resource,
            requested_operation=original_event.requested_operation if original_event else "WRITE",
            parameters=redact_secrets(validated_params),
            policy_decision="ALLOW",
            execution_status=final_status,
            execution_output=execution_output_str or fail_reason,
            risk_indicators=approval.risk_indicators,
            source_of_input=f"REVIEWER:{reviewer.username}"
        )
        db.add(audit_resolution)
        db.commit()

        approval = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()
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
        Performs atomic CAS state transition (PENDING -> REJECTED) to prevent race conditions.
        Returns HTTP 409 if the approval is currently IN_PROGRESS (and lease active).
        Guarantees that rejected operations are never dispatched to tools.
        """
        approval = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()

        if not approval:
            raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")

        now_utc = datetime.now(timezone.utc)

        # Check if actively being processed
        if approval.status == ApprovalStatus.IN_PROGRESS.value:
            is_stale, lease_age = self._is_approval_lease_expired(approval, now_utc)
            if is_stale:
                self.recover_stale_approvals(db)
                raise HTTPException(
                    status_code=400,
                    detail=f"Approval request '{approval_id}' timed out while in progress ({lease_age:.1f}s ago) and has been marked FAILED. Operation outcome is uncertain."
                )
            raise HTTPException(
                status_code=409,
                detail=f"Approval request '{approval_id}' is currently being processed and cannot be rejected."
            )

        # Check idempotency / double decision prevention
        if approval.status != ApprovalStatus.PENDING.value:
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been processed with status '{approval.status}'."
            )

        # Check expiration
        expires_at = approval.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now_utc > expires_at:
            db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id,
                ApprovalRequestModel.status == ApprovalStatus.PENDING.value
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.EXPIRED.value,
                ApprovalRequestModel.failure_reason: f"Request expired at {expires_at.isoformat()}."
            })
            db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has expired."
            )

        # Atomic Compare-and-Swap claim to REJECTED
        rows_affected = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id,
            ApprovalRequestModel.status == ApprovalStatus.PENDING.value
        ).update({
            ApprovalRequestModel.status: ApprovalStatus.REJECTED.value,
            ApprovalRequestModel.reviewed_by_user_id: reviewer.user_id,
            ApprovalRequestModel.reviewed_by_username: reviewer.username,
            ApprovalRequestModel.reviewed_at: now_utc,
            ApprovalRequestModel.review_justification: justification,
            ApprovalRequestModel.failure_reason: f"Explicitly rejected by reviewer {reviewer.username}: {justification}"
        })
        db.commit()

        if rows_affected == 0:
            current = db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == approval_id
            ).first()
            if current and current.status == ApprovalStatus.IN_PROGRESS.value:
                raise HTTPException(
                    status_code=409,
                    detail=f"Approval request '{approval_id}' is currently being processed and cannot be rejected."
                )
            current_status = current.status if current else "UNKNOWN"
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been processed with status '{current_status}'."
            )

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
            parameters=redact_secrets(approval.parameters),
            policy_decision="DENY",
            execution_status="BLOCKED",
            execution_output=f"REJECTED BY REVIEWER ({reviewer.username}): {justification}",
            risk_indicators=approval.risk_indicators,
            source_of_input=f"REVIEWER:{reviewer.username}"
        )
        db.add(audit_resolution)
        db.commit()

        approval = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.approval_id == approval_id
        ).first()
        return approval

    def _is_approval_lease_expired(
        self,
        approval: ApprovalRequestModel,
        now_utc: datetime,
        timeout_seconds: Optional[int] = None
    ) -> tuple[bool, float]:
        """
        Determines if an IN_PROGRESS approval request has exceeded its execution lease timeout.
        Returns (is_expired, age_in_seconds).
        """
        timeout = timeout_seconds if timeout_seconds is not None else settings.in_progress_lease_timeout_seconds

        # Determine reference start timestamp
        ref_time = getattr(approval, "execution_started_at", None) or approval.reviewed_at or approval.created_at
        if ref_time is None:
            return True, float(timeout + 1)

        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        age_seconds = (now_utc - ref_time).total_seconds()

        # Also check global expires_at
        expires_at = approval.expires_at
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now_utc > expires_at:
                return True, age_seconds

        return (age_seconds > timeout), age_seconds

    def recover_stale_approvals(
        self,
        db: Session,
        timeout_seconds: Optional[int] = None
    ) -> List[str]:
        """
        Scans for and safely transitions abandoned or timed-out IN_PROGRESS approval requests to FAILED.
        Guarantees:
        1. Stale requests transition to FAILED, never back to PENDING.
        2. Never automatically retries an uncertain operation.
        3. Uses atomic CAS state transitions (WHERE status = 'IN_PROGRESS') to avoid racing with active executions.
        4. Does not overwrite concurrent terminal transitions.
        5. Recovery is completely idempotent.
        """
        now_utc = datetime.now(timezone.utc)
        timeout = timeout_seconds if timeout_seconds is not None else settings.in_progress_lease_timeout_seconds

        in_progress_items = db.query(ApprovalRequestModel).filter(
            ApprovalRequestModel.status == ApprovalStatus.IN_PROGRESS.value
        ).all()

        recovered_ids: List[str] = []

        for item in in_progress_items:
            is_stale, age = self._is_approval_lease_expired(item, now_utc, timeout)
            if not is_stale:
                continue

            failure_msg = (
                f"Execution lease expired after {age:.1f}s (configured timeout: {timeout}s). "
                "The operation was abandoned or interrupted while IN_PROGRESS. "
                "The outcome is uncertain and was not automatically retried to prevent duplicate execution."
            )

            # Atomic CAS update: status must still be IN_PROGRESS
            rows_affected = db.query(ApprovalRequestModel).filter(
                ApprovalRequestModel.approval_id == item.approval_id,
                ApprovalRequestModel.status == ApprovalStatus.IN_PROGRESS.value
            ).update({
                ApprovalRequestModel.status: ApprovalStatus.FAILED.value,
                ApprovalRequestModel.failure_reason: failure_msg
            })
            db.commit()

            if rows_affected > 0:
                # Update corresponding original security event
                orig_event = db.query(SecurityEventModel).filter(
                    SecurityEventModel.event_id == item.event_id
                ).first()
                if orig_event:
                    orig_event.execution_status = ApprovalStatus.FAILED.value
                    orig_event.execution_output = failure_msg

                # Append audit resolution event
                audit_resolution = SecurityEventModel(
                    event_id=str(uuid.uuid4()),
                    timestamp=now_utc,
                    agent_id=item.agent_id,
                    session_id=item.session_id,
                    task_id=item.task_id,
                    action_type="TOOL_CALL_ABANDONED_LEASE_RECOVERED",
                    tool_name=item.tool_name,
                    resource=item.resource,
                    requested_operation=orig_event.requested_operation if orig_event else "UNKNOWN",
                    parameters=redact_secrets(item.parameters) if isinstance(item.parameters, dict) else {},
                    policy_decision="DENY",
                    execution_status="FAILED",
                    execution_output=failure_msg,
                    risk_indicators=item.risk_indicators + ["STALE_LEASE_RECOVERY"],
                    source_of_input="SYSTEM:GATEWAY_RECOVERY"
                )
                db.add(audit_resolution)
                db.commit()
                recovered_ids.append(item.approval_id)

        return recovered_ids


gateway = ToolExecutionGateway()
