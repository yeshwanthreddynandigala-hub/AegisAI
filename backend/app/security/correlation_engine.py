"""
Incident Correlation Engine.
Correlates security events, evaluates behavioral sequences and anomalies,
and synthesizes multi-event telemetry into unified causal incident timelines.
"""

from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.security.rule_detector import rule_detector, TriggeredRule

class IncidentCorrelationEngine:
    """Aggregates multi-engine detections and manages incident lifecycles."""

    def __init__(self):
        self._sequence_detector = None
        self._ml_detector = None

    def set_detectors(self, sequence_detector=None, ml_detector=None):
        self._sequence_detector = sequence_detector
        self._ml_detector = ml_detector

    def _determine_threat_category(self, triggered_rules: List[TriggeredRule], risk_indicators: List[str]) -> str:
        """Determines primary classification based on highest-severity indicator."""
        for rule in triggered_rules:
            if rule.rule_id == "RULE_B_CREDENTIAL_ACCESS":
                return "CREDENTIAL_THEFT"
            elif rule.rule_id == "RULE_C_EXFILTRATION":
                return "DATA_EXFILTRATION"
            elif rule.rule_id == "RULE_F_SANDBOX_ESCAPE":
                return "SANDBOX_ESCAPE"
            elif rule.rule_id == "RULE_G_PROMPT_INJECTION":
                return "PROMPT_INJECTION"
            elif rule.rule_id == "RULE_E_REPEATED_DENIALS":
                return "POLICY_VIOLATION_SPIKE"

        if "SENSITIVE_CREDENTIAL_ACCESS" in risk_indicators:
            return "CREDENTIAL_THEFT"
        if "DATA_EXFILTRATION_RISK" in risk_indicators:
            return "DATA_EXFILTRATION"
        if "DIRECTORY_TRAVERSAL" in risk_indicators:
            return "SANDBOX_ESCAPE"
        return "UNAUTHORIZED_ACCESS"

    def _determine_severity(self, triggered_rules: List[TriggeredRule], policy_decision: str) -> str:
        severities = [r.severity for r in triggered_rules]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        if policy_decision == "DENY":
            return "MEDIUM"
        return "LOW"

    def process_event(
        self,
        db: Session,
        current_event: SecurityEventModel,
        prior_events: List[SecurityEventModel]
    ) -> Optional[str]:
        """
        Processes a newly logged event.
        Returns the incident_id if an incident was created or updated, else None.
        """
        # 1. Evaluate Rule-Based Engine
        triggered_rules = rule_detector.evaluate_event(current_event, prior_events)

        # 2. Evaluate Behavioral Sequence Detector (if registered)
        seq_triggered = []
        if self._sequence_detector:
            seq_triggered = self._sequence_detector.evaluate_sequence(current_event, prior_events)

        # 3. Evaluate ML Anomaly Detector (if registered)
        ml_anomalous = False
        ml_score = 0.0
        if self._ml_detector:
            ml_anomalous, ml_score = self._ml_detector.evaluate_event(current_event, prior_events)

        # Determine if incident creation / update is warranted
        is_suspicious = (
            bool(triggered_rules) or
            bool(seq_triggered) or
            ml_anomalous or
            current_event.policy_decision == "DENY"
        )

        if not is_suspicious:
            return None

        # Build list of active detection engines
        detection_engines = []
        if triggered_rules:
            detection_engines.append("rule_engine")
        if seq_triggered:
            detection_engines.append("sequence_detector")
        if ml_anomalous:
            detection_engines.append("ml_anomaly")

        severity = self._determine_severity(triggered_rules, current_event.policy_decision)
        threat_cat = self._determine_threat_category(
            triggered_rules,
            current_event.risk_indicators or []
        )

        # Find existing open incident for this session
        existing_incident = db.query(IncidentModel).filter(
            IncidentModel.session_id == current_event.session_id,
            IncidentModel.status.in_(["OPEN", "INVESTIGATING"])
        ).first()

        if existing_incident:
            # Update existing incident
            evidence_ids = list(existing_incident.evidence_event_ids or [])
            if current_event.event_id not in evidence_ids:
                evidence_ids.append(current_event.event_id)
            existing_incident.evidence_event_ids = evidence_ids

            # Update engines
            curr_engines = set(existing_incident.detection_engines or [])
            curr_engines.update(detection_engines)
            existing_incident.detection_engines = list(curr_engines)

            # Escalate severity if current is higher
            severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if severity_rank.get(severity, 1) > severity_rank.get(existing_incident.severity, 1):
                existing_incident.severity = severity

            # Append summary update
            rule_names = ", ".join(r.name for r in triggered_rules) if triggered_rules else "Policy block"
            existing_incident.summary += f" | Follow-up: {rule_names} triggered at {current_event.timestamp.strftime('%H:%M:%S')}."
            existing_incident.updated_at = datetime.now(timezone.utc)

            # Link event to incident
            current_event.related_incident_id = existing_incident.incident_id
            db.commit()
            return existing_incident.incident_id

        else:
            # Create a new incident
            rule_names = ", ".join(r.name for r in triggered_rules) if triggered_rules else "Gateway policy enforcement block"
            title = f"{threat_cat.replace('_', ' ').title()} - Agent '{current_event.agent_id}'"
            summary = (
                f"Incident triggered in session '{current_event.session_id}' during task '{current_event.task_id}'. "
                f"Gateway intercepted action '{current_event.tool_name}' targeting '{current_event.resource}'. "
                f"Detections: {rule_names}. Status: {current_event.execution_status}."
            )

            new_incident = IncidentModel(
                incident_id=str(uuid.uuid4()),
                session_id=current_event.session_id,
                agent_id=current_event.agent_id,
                title=title,
                severity=severity,
                status="OPEN",
                primary_threat_category=threat_cat,
                summary=summary,
                confidence_score=0.92 if triggered_rules else 0.78,
                triggering_event_id=current_event.event_id,
                evidence_event_ids=[current_event.event_id],
                detection_engines=detection_engines or ["rule_engine"],
                mitigation_status="BLOCKED_AT_GATEWAY" if current_event.execution_status == "BLOCKED" else "REQUIRES_INVESTIGATION",
                recommendation=triggered_rules[0].recommended_response if triggered_rules else "Review agent authorization scope and session timeline."
            )
            db.add(new_incident)
            db.commit()
            db.refresh(new_incident)

            current_event.related_incident_id = new_incident.incident_id
            db.commit()
            return new_incident.incident_id

correlation_engine = IncidentCorrelationEngine()
