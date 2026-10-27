"""
Database Models for Security Telemetry and Audit Events.
Provides tamper-resistant, structured audit logs for all agent tool requests and executions.
"""

from sqlalchemy import Column, String, Text, JSON, ForeignKey
from datetime import datetime, timezone
import uuid
from app.core.database import Base, UTCDateTime

class SecurityEventModel(Base):
    __tablename__ = "security_events"

    event_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    timestamp = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), index=True)
    agent_id = Column(String(64), index=True, nullable=False)
    session_id = Column(String(64), index=True, nullable=False)
    task_id = Column(String(64), index=True, nullable=False)
    
    # Action taxonomy
    action_type = Column(String(64), index=True, nullable=False)
    tool_name = Column(String(64), nullable=True)
    resource = Column(String(256), nullable=True)
    requested_operation = Column(String(64), nullable=True)
    parameters = Column(JSON, default=dict)
    
    # Gateway enforcement
    policy_decision = Column(String(32), default="NONE")  # ALLOW, DENY, REQUIRE_APPROVAL
    execution_status = Column(String(32), default="PENDING")  # BLOCKED, EXECUTED, FAILED
    execution_output = Column(Text, nullable=True)
    
    # Security metadata
    risk_indicators = Column(JSON, default=list)
    parent_event_id = Column(String(36), nullable=True)
    source_of_input = Column(String(64), default="DIRECT_AGENT")
    related_incident_id = Column(String(36), nullable=True, index=True)
