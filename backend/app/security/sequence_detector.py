"""
Behavioral Sequence Detection Engine.
Analyzes chronological trajectories and state transitions across multi-step agent actions.
Identifies suspicious progression patterns that look innocuous when evaluated individually.
"""

from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime, timezone
from app.models.event import SecurityEventModel

class SequencePattern:
    def __init__(
        self,
        pattern_id: str,
        name: str,
        severity: str,
        state_sequence: List[str],
        description: str,
        mitigation: str
    ):
        self.pattern_id = pattern_id
        self.name = name
        self.severity = severity
        self.state_sequence = state_sequence
        self.description = description
        self.mitigation = mitigation

class BehavioralSequenceDetector:
    """State-transition and temporal pattern detector for agent sessions."""

    def __init__(self):
        # Known multi-step attack progression signatures
        self.known_patterns = [
            SequencePattern(
                pattern_id="SEQ_01_INJECTION_TO_EXFIL",
                name="Prompt Injection Leading to Exfiltration",
                severity="CRITICAL",
                state_sequence=["INDIRECT_INJECTION", "CREDENTIAL_PROBE", "NETWORK_CALL"],
                description="Agent ingested untrusted content, immediately probed restricted credential resources, and attempted outbound exfiltration.",
                mitigation="Block all outbound network calls, isolate agent session, and flag document source for quarantine."
            ),
            SequencePattern(
                pattern_id="SEQ_01B_INJECTION_TO_SCOPE_EXFIL",
                name="Prompt Injection Leading to Scope Violation & Exfiltration",
                severity="CRITICAL",
                state_sequence=["INDIRECT_INJECTION", "SCOPE_PROBE", "NETWORK_CALL"],
                description="Agent ingested untrusted content, probed out-of-scope files, and attempted outbound exfiltration.",
                mitigation="Block outbound network calls and quarantine agent session."
            ),
            SequencePattern(
                pattern_id="SEQ_02_RECON_TO_CREDENTIAL_PROBE",
                name="Reconnaissance Preceding Credential Theft",
                severity="HIGH",
                state_sequence=["BENIGN_READ", "SCOPE_PROBE", "CREDENTIAL_PROBE"],
                description="Agent performed normal reads, shifted to exploring out-of-scope files, and directly targeted credential honeytokens.",
                mitigation="Revoke file reading permissions, freeze active task, and check for hidden prompt steering."
            ),
            SequencePattern(
                pattern_id="SEQ_03_STEALTH_PROBING",
                name="Stealthy Multi-Vector Probing",
                severity="MEDIUM",
                state_sequence=["SEARCH", "TOOL_VIOLATION", "TOOL_VIOLATION"],
                description="Agent performed exploratory search followed by multiple prohibited tool requests across different vectors.",
                mitigation="Alert SOC analyst to verify if agent goal was under-specified or if agent drifted."
            ),
            SequencePattern(
                pattern_id="SEQ_04_REPEATED_CREDENTIAL_PROBE",
                name="Repeated Credential Probing Surge",
                severity="CRITICAL",
                state_sequence=["CREDENTIAL_PROBE", "CREDENTIAL_PROBE"],
                description="Agent performed repeated unauthorized queries against credential storage locations.",
                mitigation="Immediately quarantine session and revoke all data reading access."
            )
        ]

    def _event_to_state(self, event: SecurityEventModel) -> str:
        """Translates a raw security event into an abstract behavioral state token."""
        if not event:
            return "GENERIC_ACTION"

        indicators = event.risk_indicators or []
        indicators_str = " ".join(indicators).upper()

        # 1. Credential probing / Honeytokens (highest priority operation risk)
        if any(k in indicators_str for k in ["CREDENTIAL", "HONEYTOKEN"]):
            return "CREDENTIAL_PROBE"

        # 2. Network exfiltration / outbound beaconing
        if (
            any(k in indicators_str for k in ["EXFILTRATION", "UNAPPROVED_DESTINATION", "UNAPPROVED_DOMAIN"])
            or event.requested_operation == "NETWORK_CALL"
            or (event.tool_name in ["mock_api_request", "browser_open"] and event.policy_decision == "DENY")
        ):
            return "NETWORK_CALL"

        # 3. Path Traversal and Scope Violations
        if any(k in indicators_str for k in ["TRAVERSAL", "ESCAPE", "SCOPE_VIOLATION", "RESTRICTED_FILE"]):
            return "SCOPE_PROBE"

        # 4. Prohibited tool or operation violations
        if any(k in indicators_str for k in ["UNAUTHORIZED_TOOL", "TOOL_NOT_PERMITTED", "UNAUTHORIZED_OPERATION"]):
            return "TOOL_VIOLATION"

        # 5. Indirect Injection / Untrusted prompt injection source
        if (
            event.source_of_input == "INDIRECT_INJECTION"
            or any(k in indicators_str for k in ["INJECTION", "UNTRUSTED_INDIRECT_INPUT"])
        ):
            return "INDIRECT_INJECTION"

        # 6. Search operation
        if event.tool_name == "browser_search" or event.requested_operation == "SEARCH":
            return "SEARCH"

        # 7. Benign authorized reads / data queries
        if (
            (event.action_type == "TOOL_CALL_ALLOWED" or event.policy_decision == "ALLOW")
            and event.requested_operation in ["READ", "CALCULATE", "DB_QUERY"]
        ):
            return "BENIGN_READ"

        # 8. Write attempts
        if event.requested_operation == "WRITE" or event.tool_name == "filesystem_write":
            return "WRITE_ATTEMPT"

        return "GENERIC_ACTION"

    def evaluate_sequence(
        self,
        current_event: SecurityEventModel,
        prior_events: List[SecurityEventModel]
    ) -> List[Dict[str, Any]]:
        """
        Evaluates the chronological trajectory of states in the session.
        Returns triggered sequence detection descriptors.
        """
        def _ts_key(e: SecurityEventModel) -> float:
            ts = getattr(e, "timestamp", None)
            if ts is None:
                return 0.0
            if isinstance(ts, datetime):
                try:
                    return ts.timestamp()
                except Exception:
                    return 0.0
            return 0.0

        full_events = list(prior_events) + [current_event]
        full_events.sort(key=_ts_key)
        states = [self._event_to_state(e) for e in full_events]

        detections = []
        matched_pattern_ids = set()

        for pattern in self.known_patterns:
            target_seq = pattern.state_sequence
            seq_len = len(target_seq)

            for i in range(len(states) - seq_len + 1):
                window = states[i: i + seq_len]
                if window == target_seq:
                    if pattern.pattern_id not in matched_pattern_ids:
                        matched_pattern_ids.add(pattern.pattern_id)
                        detections.append({
                            "pattern_id": pattern.pattern_id,
                            "name": pattern.name,
                            "severity": pattern.severity,
                            "matched_states": window,
                            "window_event_ids": [e.event_id for e in full_events[i: i + seq_len]],
                            "description": pattern.description,
                            "mitigation": pattern.mitigation,
                            "detected_at": datetime.now(timezone.utc).isoformat()
                        })

        return detections

sequence_detector = BehavioralSequenceDetector()
