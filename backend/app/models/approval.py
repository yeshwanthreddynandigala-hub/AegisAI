"""
Database Model for Human-in-the-Loop (HITL) Security Approval Requests.
Tracks deferred agent tool invocations requiring human authorization before execution.
Enforces an explicit audit trail: reviewer identity, decision justification, timestamps,
and execution outcome.
"""

from sqlalchemy import Column, String, Text, JSON, ForeignKey
from datetime import datetime, timezone
import uuid
import enum

from app.core.database import Base, UTCDateTime


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class ApprovalRequestModel(Base):
    __tablename__ = "approval_requests"

    approval_id = Column(String(36), primary_key=True, default=lambda: f"appr-{uuid.uuid4().hex[:12]}", index=True)
    event_id = Column(String(36), ForeignKey("security_events.event_id"), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    task_id = Column(String(64), nullable=False, index=True)

    # Action details
    tool_name = Column(String(64), nullable=False, index=True)
    parameters = Column(JSON, default=dict)
    resource = Column(String(256), nullable=True)

    # Policy details
    decision_reason = Column(Text, nullable=True)
    risk_indicators = Column(JSON, default=list)

    # Lifecycle state
    status = Column(String(32), default=ApprovalStatus.PENDING.value, nullable=False, index=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    expires_at = Column(UTCDateTime, nullable=False, index=True)
    execution_started_at = Column(UTCDateTime, nullable=True, index=True)

    # Review audit
    reviewed_by_user_id = Column(String(36), nullable=True)
    reviewed_by_username = Column(String(64), nullable=True)
    reviewed_at = Column(UTCDateTime, nullable=True)
    review_justification = Column(Text, nullable=True)

    # Execution outcome
    execution_output = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)
