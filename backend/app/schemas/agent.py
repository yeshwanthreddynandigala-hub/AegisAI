"""
Pydantic Schemas for Agent Identity and Policy Manifest.
"""

from pydantic import BaseModel, Field, ConfigDict, field_serializer
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

class PolicyManifestBase(BaseModel):
    version: str = "1.0"
    allowed_tools: List[str] = Field(default_factory=list, description="Whitelist of tool names")
    allowed_paths: List[str] = Field(default_factory=list, description="Glob patterns for allowed file access")
    denied_paths: List[str] = Field(default_factory=list, description="Explicit blacklist patterns")
    allowed_network_domains: List[str] = Field(default_factory=list, description="Allowed mock external domains")
    allowed_operations: List[str] = Field(default_factory=list, description="Allowed action primitives (READ, SEARCH, etc.)")
    require_approval_operations: List[str] = Field(default_factory=list, description="Actions pausing for human approval")
    max_denial_threshold: int = Field(default=3, description="Max failed attempts before session freeze")

class PolicyManifestCreate(PolicyManifestBase):
    pass

class PolicyManifestResponse(PolicyManifestBase):
    policy_id: str
    agent_id: str
    created_at: datetime

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime) -> str:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    model_config = ConfigDict(from_attributes=True)

class AgentBase(BaseModel):
    name: str
    role: str
    description: Optional[str] = None
    authorized_objective: str
    is_active: bool = True

class AgentCreate(AgentBase):
    agent_id: str
    policy: PolicyManifestCreate

class AgentResponse(AgentBase):
    agent_id: str
    created_at: datetime
    updated_at: datetime
    policy: Optional[PolicyManifestResponse] = None

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
