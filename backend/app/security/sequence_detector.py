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
                state_sequence=["INDIRECT_INJECTION", "RESTRICTED_ACCESS", "NETWORK_CALL"],
                description="Agent ingested untrusted content, immediately probed restricted resources, and attempted outbound exfiltration.",
                mitigation="Block all outbound network calls, isolate agent session, and flag document source for quarantine."
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
            )
        ]

    def _event_to_state(self, event: SecurityEventModel) -> str:
        """Translates a raw security event into an abstract behavioral state token."""
        indicators = event.risk_indicators or []
        
        if event.source_of_input == "INDIRECT_INJECTION":
            return "INDIRECT_INJECTION"
        if any("CREDENTIAL" in ind for ind in indicators):
            return "CREDENTIAL_PROBE"
        if any("EXFILTRATION" in ind for ind in indicators) or event.requested_operation == "NETWORK_CALL":
            return "NETWORK_CALL"
        if any("TRAVERSAL" in ind or "ESCAPE" in ind for ind in indicators):
            return "SCOPE_PROBE"
        if "SCOPE_VIOLATION" in indicators:
            return "SCOPE_PROBE"
        if "UNAUTHORIZED_TOOL_INVOCATION" in indicators:
            return "TOOL_VIOLATION"
        if event.action_type == "TOOL_CALL_ALLOWED" and event.requested_operation == "READ":
            return "BENIGN_READ"
        if event.tool_name == "browser_search":
            return "SEARCH"
        if event.requested_operation == "WRITE":
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
        # Build full session state sequence
        full_events = list(prior_events) + [current_event]
        states = [self._event_to_state(e) for e in full_events]

        detections = []

        # Check known malicious sequence subsequences
        for pattern in self.known_patterns:
            target_seq = pattern.state_sequence
            seq_len = len(target_seq)
            
            # Slide window across observed states
            for i in range(len(states) - seq_len + 1):
                window = states[i: i + seq_len]
                # Compare fuzzy match or exact match
                if window == target_seq:
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
