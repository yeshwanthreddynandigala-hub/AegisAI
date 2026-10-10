"""
Rule-Based Security Detection Engine.
Implements deterministic, transparent detection rules for known AI-agent attack patterns.
Cites exact event evidence and provides actionable SecOps recommendations.
"""

from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime, timezone
from app.models.event import SecurityEventModel

class TriggeredRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,  # LOW, MEDIUM, HIGH, CRITICAL
        explanation: str,
        recommended_response: str,
        related_event_id: str,
        risk_indicators: List[str]
    ):
        self.detection_id = str(uuid.uuid4())
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.explanation = explanation
        self.recommended_response = recommended_response
        self.related_event_id = related_event_id
        self.risk_indicators = risk_indicators
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "explanation": self.explanation,
            "recommended_response": self.recommended_response,
            "related_event_id": self.related_event_id,
            "risk_indicators": self.risk_indicators,
            "timestamp": self.timestamp.isoformat()
        }

class RuleBasedDetector:
    """Evaluates telemetry events against transparent security rule definitions."""

    def evaluate_event(
        self,
        event: SecurityEventModel,
        prior_session_events: List[SecurityEventModel]
    ) -> List[TriggeredRule]:
        """Runs rule checks against current event and session context."""
        triggered = []

        # Rule B: Simulated Credential Access Attempt
        if any(ind in (event.risk_indicators or []) for ind in ["SENSITIVE_CREDENTIAL_ACCESS", "DATABASE_HONEYTOKEN_HIT"]):
            triggered.append(TriggeredRule(
                rule_id="RULE_B_CREDENTIAL_ACCESS",
                name="Credential Harvest / Honeytoken Access Attempt",
                severity="CRITICAL",
                explanation=f"Agent attempted access to simulated credentials or secret token resource '{event.resource}'.",
                recommended_response="Block session immediately, inspect prompt provenance for prompt-injection markers, and rotate affected synthetic keys.",
                related_event_id=event.event_id,
                risk_indicators=["CREDENTIAL_THEFT", "HONEYTOKEN_TRIGGER"]
            ))

        # Rule C: Unapproved Network Destination / Exfiltration Attempt
        if "DATA_EXFILTRATION_RISK" in (event.risk_indicators or []):
            triggered.append(TriggeredRule(
                rule_id="RULE_C_EXFILTRATION",
                name="Unauthorized Data Exfiltration / Mock Endpoint Beacon",
                severity="HIGH",
                explanation=f"Agent attempted to dispatch outbound network call to unapproved endpoint '{event.resource}'.",
                recommended_response="Enforce gateway firewall block and inspect payload for staged sensitive variables.",
                related_event_id=event.event_id,
                risk_indicators=["DATA_EXFILTRATION", "UNAPPROVED_DESTINATION"]
            ))

        # Rule F: Sandbox Escape / Directory Traversal Attempt
        if "DIRECTORY_TRAVERSAL" in (event.risk_indicators or []):
            triggered.append(TriggeredRule(
                rule_id="RULE_F_SANDBOX_ESCAPE",
                name="Directory Traversal / Filesystem Sandbox Escape Attempt",
                severity="CRITICAL",
                explanation=f"Tool parameters contained relative or root traversal patterns targeting '{event.resource}'.",
                recommended_response="Quarantine agent session and verify canonical sandbox boundaries.",
                related_event_id=event.event_id,
                risk_indicators=["SANDBOX_ESCAPE", "PATH_TRAVERSAL"]
            ))

        # Rule D: Prohibited Tool / Operation Invocations
        if "UNAUTHORIZED_TOOL_INVOCATION" in (event.risk_indicators or []):
            triggered.append(TriggeredRule(
                rule_id="RULE_D_PROHIBITED_OPERATION",
                name="Prohibited Tool Invocation Attempt",
                severity="MEDIUM",
                explanation=f"Agent attempted to invoke tool '{event.tool_name}' which is disallowed by its policy manifest.",
                recommended_response="Audit agent prompt alignment and review tool whitelist requirements.",
                related_event_id=event.event_id,
                risk_indicators=["PRIVILEGE_VIOLATION"]
            ))

        # Rule A: Out-of-Scope Resource Access
        if "SCOPE_VIOLATION" in (event.risk_indicators or []):
            triggered.append(TriggeredRule(
                rule_id="RULE_A_OUT_OF_SCOPE_ACCESS",
                name="Out-of-Scope Resource Access Attempt",
                severity="MEDIUM",
                explanation=f"Agent requested access to path '{event.resource}' outside its defined least-privilege scope.",
                recommended_response="Verify if user objective necessitated this resource; expand policy scope if legitimate.",
                related_event_id=event.event_id,
                risk_indicators=["SCOPE_DEVIATION"]
            ))

        # Rule E: Repeated Policy Denial Storm
        denied_in_session = sum(
            1 for pe in prior_session_events
            if pe.policy_decision == "DENY" or pe.execution_status == "BLOCKED"
        )
        if event.policy_decision == "DENY":
            denied_in_session += 1

        if denied_in_session >= 3:
            triggered.append(TriggeredRule(
                rule_id="RULE_E_REPEATED_DENIALS",
                name="Excessive Policy Denial Threshold Exceeded",
                severity="HIGH",
                explanation=f"Agent has triggered {denied_in_session} consecutive or repeated policy blocks within session '{event.session_id}'.",
                recommended_response="Lock agent session, trigger automated incident investigation, and disconnect active execution loop.",
                related_event_id=event.event_id,
                risk_indicators=["REPEATED_POLICY_VIOLATIONS", "AUTOMATED_PROBING"]
            ))

        # Rule G: Indirect Prompt Injection Marker in Input
        if event.source_of_input == "INDIRECT_INJECTION" or "PROMPT_INJECTION_DETECTED" in (event.risk_indicators or []):
            triggered.append(TriggeredRule(
                rule_id="RULE_G_PROMPT_INJECTION",
                name="Indirect Prompt Injection Payload Detected",
                severity="CRITICAL",
                explanation="Input data ingested by the agent contained adversarial prompt override instructions.",
                recommended_response="Isolate untrusted document, scrub retrieved context window, and review downstream tool calls.",
                related_event_id=event.event_id,
                risk_indicators=["INDIRECT_PROMPT_INJECTION", "ADVERSARIAL_PAYLOAD"]
            ))

        return triggered

rule_detector = RuleBasedDetector()
