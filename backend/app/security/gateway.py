"""
Tool Execution Gateway (Zero-Trust Mediation Layer).
Intercepts all agent tool invocations, enforces access policy, sanitizes telemetry,
and blocks unauthorized operations BEFORE they reach system or synthetic resources.
"""

from typing import Dict, Any, Optional, List
import uuid
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
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
            audit_event = SecurityEventModel(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
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
            db.commit()

            return ToolCallResponse(
                event_id=event_id,
                policy_decision="REQUIRE_APPROVAL",
                execution_status="PENDING",
                decision_reason=policy_result.message,
                output=None,
                risk_indicators=policy_result.risk_indicators
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

gateway = ToolExecutionGateway()
