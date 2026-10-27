"""
Database Models for Agents and Security Policies.
Defines agent identities, authorized scopes, and access control policies.
"""

from sqlalchemy import Column, String, Integer, Boolean, Text, JSON
from datetime import datetime, timezone
from app.core.database import Base, UTCDateTime

class AgentModel(Base):
    __tablename__ = "agents"

    agent_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    role = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    authorized_objective = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class PolicyManifestModel(Base):
    __tablename__ = "policy_manifests"

    policy_id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), index=True, nullable=False)
    version = Column(String(16), default="1.0")
    
    # Tool whitelist (e.g., ["document_reader", "calculator"])
    allowed_tools = Column(JSON, default=list)
    
    # Path access controls
    allowed_paths = Column(JSON, default=list)  # Glob patterns e.g. ["public/*", "reports/*.pdf"]
    denied_paths = Column(JSON, default=list)   # Explicit denials e.g. ["credentials/*", "private/*"]
    
    # Network whitelist for mock external calls
    allowed_network_domains = Column(JSON, default=list)
    
    # Operation constraints
    allowed_operations = Column(JSON, default=list) # e.g. ["READ", "SEARCH", "CALCULATE"]
    require_approval_operations = Column(JSON, default=list) # e.g. ["WRITE", "DELETE"]
    
    # Denial threshold before session quarantine
    max_denial_threshold = Column(Integer, default=3)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
