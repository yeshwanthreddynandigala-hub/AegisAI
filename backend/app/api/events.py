"""
API Router: Security Events & Telemetry.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.models.event import SecurityEventModel
from app.schemas.event import SecurityEventResponse, ToolCallRequest, ToolCallResponse
from app.security.gateway import gateway

router = APIRouter(prefix="/events", tags=["Events"])

@router.get("", response_model=List[SecurityEventResponse])
def list_events(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    policy_decision: Optional[str] = Query(None, description="Filter by decision (ALLOW/DENY/REQUIRE_APPROVAL)"),
    execution_status: Optional[str] = Query(None, description="Filter by execution status (EXECUTED/BLOCKED)"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieve audit events with comprehensive SOC filtering."""
    q = db.query(SecurityEventModel)
    if session_id:
        q = q.filter(SecurityEventModel.session_id == session_id)
    if agent_id:
        q = q.filter(SecurityEventModel.agent_id == agent_id)
    if policy_decision:
        q = q.filter(SecurityEventModel.policy_decision == policy_decision.upper())
    if execution_status:
        q = q.filter(SecurityEventModel.execution_status == execution_status.upper())

    events = q.order_by(SecurityEventModel.timestamp.desc()).offset(offset).limit(limit).all()
    return [SecurityEventResponse.model_validate(e) for e in events]

@router.get("/{event_id}", response_model=SecurityEventResponse)
def get_event(event_id: str, db: Session = Depends(get_db)):
    """Retrieve specific event telemetry by event ID."""
    evt = db.query(SecurityEventModel).filter(SecurityEventModel.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    return SecurityEventResponse.model_validate(evt)

@router.post("/execute", response_model=ToolCallResponse)
def execute_tool_call(req: ToolCallRequest, db: Session = Depends(get_db)):
    """
    Submits a tool call to the zero-trust execution gateway.
    Action is evaluated and blocked or executed before returning.
    """
    return gateway.dispatch_tool_call(db=db, request=req)
