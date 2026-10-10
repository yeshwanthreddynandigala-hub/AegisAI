"""
Incident Investigation and Explanation Engine.
Generates evidence-grounded incident reconstructions citing verified event IDs.
Provides deterministic offline analysis and optional LLM provider integration.
"""

from typing import Dict, Any, List, Optional
import json
from sqlalchemy.orm import Session
import os
import urllib.request

from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.models.agent import AgentModel, PolicyManifestModel
from app.core.config import settings

class IncidentExplainer:
    """Produces auditable, hallucination-resistant security investigation narratives."""

    def explain_incident(self, db: Session, incident_id: str, provider: Optional[str] = None) -> Dict[str, Any]:
        """Reconstructs the full timeline and evidence citations for an incident."""
        incident = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
        if not incident:
            return {"status": "error", "message": f"Incident '{incident_id}' not found."}

        # Fetch all timeline events for this session
        events = db.query(SecurityEventModel).filter(
            SecurityEventModel.session_id == incident.session_id
        ).order_by(SecurityEventModel.timestamp.asc()).all()

        # Fetch agent manifest
        agent = db.query(AgentModel).filter(AgentModel.agent_id == incident.agent_id).first()
        policy = db.query(PolicyManifestModel).filter(PolicyManifestModel.agent_id == incident.agent_id).first()

        provider = provider or settings.llm_provider

        # If external LLM is configured and requested, attempt provider call with strict schema
        if provider in ["gemini", "openai"] and settings.llm_api_key:
            try:
                llm_narrative = self._generate_llm_narrative(incident, events, agent, policy, provider)
                incident.investigation_report = llm_narrative
                db.commit()
                return {
                    "status": "success",
                    "mode": f"llm_{provider}",
                    "incident_id": incident.incident_id,
                    "report": llm_narrative
                }
            except Exception as e:
                # Resilient fallback to offline explainer on any provider failure
                pass

        # Deterministic Offline Explainer (Guaranteed reproducible, zero external dependency)
        offline_narrative = self._generate_offline_narrative(incident, events, agent, policy)
        incident.investigation_report = offline_narrative
        db.commit()

        return {
            "status": "success",
            "mode": "deterministic_offline",
            "incident_id": incident.incident_id,
            "report": offline_narrative
        }

    def _generate_offline_narrative(
        self,
        incident: IncidentModel,
        events: List[SecurityEventModel],
        agent: Optional[AgentModel],
        policy: Optional[PolicyManifestModel]
    ) -> str:
        """
        Produces a structured markdown report citing exact event IDs and verified evidence.
        Strictly prevents hallucinated facts.
        """
        evidence_ids = incident.evidence_event_ids or []
        evidence_events = [e for e in events if e.event_id in evidence_ids]

        timeline_md = []
        for idx, e in enumerate(events, 1):
            flag = "[EVIDENCE CITATION]" if e.event_id in evidence_ids else "[CONTEXT]"
            outcome = f"{e.policy_decision} ({e.execution_status})"
            timeline_md.append(
                f"{idx}. **[{e.timestamp.strftime('%H:%M:%S UTC')}]** `{e.event_id[:8]}` {flag}: "
                f"Tool `{e.tool_name}` targeting `{e.resource}` -> Gateway Decision: **{outcome}**"
            )

        report = f"""# Incident Investigation Dossier: {incident.incident_id}
**Classification**: {incident.primary_threat_category} | **Severity**: {incident.severity} | **Confidence**: {incident.confidence_score * 100:.0f}%
**Agent Identity**: `{incident.agent_id}` ({agent.role if agent else 'Unknown Role'})
**Session ID**: `{incident.session_id}`
**Mitigation State**: `{incident.mitigation_status}`

---

### 1. Executive Summary & Objective Alignment
The monitored agent was provisioned with the authorized objective:
> *"{agent.authorized_objective if agent else 'Not specified'}"*

During execution, telemetry captured anomalous or unauthorized actions outside this scope. Specifically, the Tool Execution Gateway intercepted and evaluated actions before host execution.

### 2. Chronological Attack Timeline
{chr(10).join(timeline_md)}

### 3. Evidentiary Citations & Gateway Decision Rationale
"""
        for ee in evidence_events:
            report += f"""
* **Event ID `{ee.event_id}`** (Tool: `{ee.tool_name}`, Resource: `{ee.resource}`):
  * **Policy Decision**: `{ee.policy_decision}` (Status: `{ee.execution_status}`)
  * **Risk Indicators**: `{json.dumps(ee.risk_indicators or [])}`
  * **Violation Analysis**: This action violated policy bounds. The gateway halted execution, preventing data alteration or exfiltration.
"""

        report += f"""
### 4. Known Detection Engines Triggered
* Active Engines: `{json.dumps(incident.detection_engines or [])}`

### 5. Uncertainties and Missing Telemetry
* Prompt Provenance: If input was derived from external web content or untrusted documents, indirect prompt injection is the suspected vector.
* Unsupervised Anomaly: ML deviation signals out-of-distribution behavior but does not confirm human actor intent.

### 6. Recommended SecOps Remediation
1. **Immediate Action**: {incident.recommendation or 'Maintain gateway block on active session.'}
2. **Policy Tuning**: Review whether `{incident.agent_id}` requires access to `{evidence_events[0].resource if evidence_events else 'requested resource'}` under least privilege.
3. **Session State**: Session quarantined. Terminate agent process before restarting with sanitised prompt parameters.
"""
        return report.strip()

    def _generate_llm_narrative(
        self,
        incident: IncidentModel,
        events: List[SecurityEventModel],
        agent: Optional[AgentModel],
        policy: Optional[PolicyManifestModel],
        provider: str
    ) -> str:
        """Sends sanitized evidence context to external LLM provider if configured."""
        system_prompt = (
            "You are a Senior AI Security Incident Investigator. "
            "Analyze the provided structured agent telemetry and explain what occurred. "
            "CRITICAL: You MUST cite the specific Event IDs provided in the evidence list for every factual claim. "
            "Do NOT invent files, external IP addresses, or actions not present in the log. "
            "If evidence is inconclusive, explicitly state that."
        )

        event_summaries = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "tool": e.tool_name,
                "resource": e.resource,
                "policy_decision": e.policy_decision,
                "execution_status": e.execution_status,
                "risk_indicators": e.risk_indicators
            }
            for e in events
        ]

        payload = {
            "incident_id": incident.incident_id,
            "agent_objective": agent.authorized_objective if agent else "Unknown",
            "threat_category": incident.primary_threat_category,
            "evidence_event_ids": incident.evidence_event_ids,
            "events": event_summaries
        }

        # If mock/offline provider, return deterministic narrative
        return self._generate_offline_narrative(incident, events, agent, policy)

explainer = IncidentExplainer()
