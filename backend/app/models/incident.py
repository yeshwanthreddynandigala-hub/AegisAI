"""
Database Models for Security Incidents and Attack Timelines.
Represents correlated clusters of suspicious telemetry events with causal evidence.
"""

from sqlalchemy import Column, String, Text, JSON, Float
from datetime import datetime, timezone
import uuid
from app.core.database import Base, UTCDateTime

class IncidentModel(Base):
    __tablename__ = "incidents"

    incident_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    session_id = Column(String(64), index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=False)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), default="MEDIUM", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default="OPEN", index=True) # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    
    primary_threat_category = Column(String(64), nullable=False)
    summary = Column(Text, nullable=False)
    confidence_score = Column(Float, default=0.85)
    
    triggering_event_id = Column(String(36), nullable=False)
    evidence_event_ids = Column(JSON, default=list)  # List of UUID strings
    detection_engines = Column(JSON, default=list)   # ["rule_engine", "sequence_detector", "ml_anomaly"]
    mitigation_status = Column(String(64), default="BLOCKED_AT_GATEWAY")
    
    recommendation = Column(Text, nullable=True)
    investigation_report = Column(Text, nullable=True)
    
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
