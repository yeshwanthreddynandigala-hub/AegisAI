"""
Pydantic Schemas for Human-in-the-Loop (HITL) Security Approvals.
"""

from pydantic import BaseModel, Field, ConfigDict, field_serializer
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


class ApprovalDecisionRequest(BaseModel):
    justification: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="Mandatory reviewer justification for the security decision."
    )


class ApprovalRequestResponse(BaseModel):
    approval_id: str
    event_id: str
    agent_id: str
    session_id: str
    task_id: str
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    resource: Optional[str] = None
    status: str
    decision_reason: Optional[str] = None
    risk_indicators: List[str] = Field(default_factory=list)
    created_at: datetime
    expires_at: datetime
    reviewed_by_user_id: Optional[str] = None
    reviewed_by_username: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_justification: Optional[str] = None
    execution_output: Optional[str] = None
    failure_reason: Optional[str] = None

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime) -> Optional[str]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_serializer("expires_at")
    def serialize_expires_at(self, dt: datetime) -> Optional[str]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_serializer("reviewed_at")
    def serialize_reviewed_at(self, dt: Optional[datetime]) -> Optional[str]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    model_config = ConfigDict(from_attributes=True)
