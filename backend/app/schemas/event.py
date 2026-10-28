"""
Pydantic Schemas for Security Telemetry Events.
"""

from pydantic import BaseModel, Field, ConfigDict, field_serializer
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from app.core.sanitizer import redact_secrets

class ToolCallRequest(BaseModel):
    agent_id: str
    session_id: str
    task_id: str
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    source_of_input: str = "DIRECT_AGENT"

class ToolCallResponse(BaseModel):
    event_id: str
    policy_decision: str  # ALLOW, DENY, REQUIRE_APPROVAL
    execution_status: str  # EXECUTED, BLOCKED, FAILED, PENDING
    decision_reason: str
    output: Optional[Any] = None
    risk_indicators: List[str] = Field(default_factory=list)
    incident_created: bool = False
    incident_id: Optional[str] = None
    approval_id: Optional[str] = None

class SecurityEventResponse(BaseModel):
    event_id: str
    timestamp: datetime
    agent_id: str
    session_id: str
    task_id: str
    action_type: str
    tool_name: Optional[str] = None
    resource: Optional[str] = None
    requested_operation: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    policy_decision: str
    execution_status: str
    execution_output: Optional[str] = None
    risk_indicators: List[str] = Field(default_factory=list)
    parent_event_id: Optional[str] = None
    source_of_input: str
    related_incident_id: Optional[str] = None

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime) -> str:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_serializer("parameters")
    def serialize_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return redact_secrets(params)

    @field_serializer("execution_output")
    def serialize_execution_output(self, out: Optional[str]) -> Optional[str]:
        if out is None:
            return None
        return redact_secrets(out)

    model_config = ConfigDict(from_attributes=True)

class EventFilterParams(BaseModel):
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    policy_decision: Optional[str] = None
    execution_status: Optional[str] = None
    action_type: Optional[str] = None
    limit: int = 100
    offset: int = 0
