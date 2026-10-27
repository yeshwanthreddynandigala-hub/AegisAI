"""
API Router: Security Incidents & Investigations.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.incident import IncidentModel
from app.models.event import SecurityEventModel
from app.models.user import UserModel
from app.schemas.incident import IncidentResponse, IncidentInvestigationDetail, InvestigateRequest
from app.schemas.event import SecurityEventResponse
from app.investigation.explainer import explainer
from app.api.deps import get_current_user, require_admin

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity (LOW/MEDIUM/HIGH/CRITICAL)"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN/INVESTIGATING/CONTAINED)"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Retrieve security incidents with severity filters."""
    q = db.query(IncidentModel)
    if severity:
        q = q.filter(IncidentModel.severity == severity.upper())
    if status:
        q = q.filter(IncidentModel.status == status.upper())

    incidents = q.order_by(IncidentModel.created_at.desc()).limit(limit).all()
    return [IncidentResponse.model_validate(inc) for inc in incidents]

@router.get("/{incident_id}", response_model=IncidentInvestigationDetail)
def get_incident_detail(incident_id: str, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """Retrieve deep incident investigation view including complete chronological timeline."""
    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    events = db.query(SecurityEventModel).filter(
        SecurityEventModel.session_id == inc.session_id
    ).order_by(SecurityEventModel.timestamp.asc()).all()

    detail = IncidentInvestigationDetail.model_validate(inc)
    detail.timeline_events = [SecurityEventResponse.model_validate(e) for e in events]
    return detail

@router.post("/{incident_id}/investigate")
def trigger_investigation(
    incident_id: str,
    payload: Optional[InvestigateRequest] = None,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Generates an evidence-grounded investigation narrative citing verified event IDs."""
    provider = payload.provider if payload else "offline"
    result = explainer.explain_incident(db=db, incident_id=incident_id, provider=provider)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("message"))
    return result

@router.post("/{incident_id}/contain")
def contain_incident(incident_id: str, db: Session = Depends(get_db), admin_user: UserModel = Depends(require_admin)):
    """Sets incident status to CONTAINED (Admin privilege required)."""
    inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    inc.status = "CONTAINED"
    inc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inc)
    return {"status": "success", "message": f"Incident {incident_id} marked as CONTAINED."}
