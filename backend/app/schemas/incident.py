"""
Pydantic Schemas for Incidents and Timeline Views.
"""

from pydantic import BaseModel, Field, ConfigDict, field_serializer
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from app.schemas.event import SecurityEventResponse

class IncidentBase(BaseModel):
    session_id: str
    agent_id: str
    title: str
    severity: str
    status: str = "OPEN"
    primary_threat_category: str
    summary: str
    confidence_score: float = 0.85
    mitigation_status: str = "BLOCKED_AT_GATEWAY"
    recommendation: Optional[str] = None

class IncidentCreate(IncidentBase):
    triggering_event_id: str
    evidence_event_ids: List[str] = Field(default_factory=list)
    detection_engines: List[str] = Field(default_factory=list)

class IncidentResponse(IncidentBase):
    incident_id: str
    triggering_event_id: str
    evidence_event_ids: List[str] = Field(default_factory=list)
    detection_engines: List[str] = Field(default_factory=list)
    investigation_report: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime) -> str:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_serializer("updated_at")
    def serialize_updated_at(self, dt: datetime) -> str:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    model_config = ConfigDict(from_attributes=True)

class IncidentInvestigationDetail(IncidentResponse):
    timeline_events: List[SecurityEventResponse] = Field(default_factory=list)
    policy_clauses_violated: List[str] = Field(default_factory=list)
    mitigation_steps: List[str] = Field(default_factory=list)

class InvestigateRequest(BaseModel):
    provider: Optional[str] = "offline"  # offline, gemini, etc.
