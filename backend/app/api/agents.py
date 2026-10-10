"""
API Router: Agents and Security Policies.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import uuid

from app.core.database import get_db
from app.models.agent import AgentModel, PolicyManifestModel
from app.schemas.agent import AgentCreate, AgentResponse, PolicyManifestResponse

router = APIRouter(prefix="/agents", tags=["Agents"])

@router.get("", response_model=List[AgentResponse])
def list_agents(db: Session = Depends(get_db)):
    """List all registered monitored AI agents and their active policies."""
    agents = db.query(AgentModel).all()
    res = []
    for ag in agents:
        policy = db.query(PolicyManifestModel).filter(PolicyManifestModel.agent_id == ag.agent_id).first()
        ag_data = AgentResponse.model_validate(ag)
        if policy:
            ag_data.policy = PolicyManifestResponse.model_validate(policy)
        res.append(ag_data)
    return res

@router.get("/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, db: Session = Depends(get_db)):
    """Get detailed agent identity and policy configuration."""
    ag = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not ag:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    policy = db.query(PolicyManifestModel).filter(PolicyManifestModel.agent_id == agent_id).first()
    ag_data = AgentResponse.model_validate(ag)
    if policy:
        ag_data.policy = PolicyManifestResponse.model_validate(policy)
    return ag_data

@router.post("", response_model=AgentResponse)
def create_agent(payload: AgentCreate, db: Session = Depends(get_db)):
    """Register a new controlled AI agent and assign its security manifest."""
    existing = db.query(AgentModel).filter(AgentModel.agent_id == payload.agent_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Agent '{payload.agent_id}' already exists.")

    new_agent = AgentModel(
        agent_id=payload.agent_id,
        name=payload.name,
        role=payload.role,
        description=payload.description,
        authorized_objective=payload.authorized_objective,
        is_active=payload.is_active
    )
    db.add(new_agent)

    new_policy = PolicyManifestModel(
        policy_id=str(uuid.uuid4()),
        agent_id=payload.agent_id,
        version=payload.policy.version,
        allowed_tools=payload.policy.allowed_tools,
        allowed_paths=payload.policy.allowed_paths,
        denied_paths=payload.policy.denied_paths,
        allowed_network_domains=payload.policy.allowed_network_domains,
        allowed_operations=payload.policy.allowed_operations,
        require_approval_operations=payload.policy.require_approval_operations,
        max_denial_threshold=payload.policy.max_denial_threshold
    )
    db.add(new_policy)
    db.commit()
    db.refresh(new_agent)

    resp = AgentResponse.model_validate(new_agent)
    resp.policy = PolicyManifestResponse.model_validate(new_policy)
    return resp
