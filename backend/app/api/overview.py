"""
API Router: Overview Dashboard Summary Statistics.
Supplies real, live backend counts, distributions, and recent incidents.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any, List

from app.core.database import get_db
from app.models.agent import AgentModel
from app.models.event import SecurityEventModel
from app.models.incident import IncidentModel
from app.schemas.incident import IncidentResponse
from app.schemas.event import SecurityEventResponse

router = APIRouter(prefix="/overview", tags=["Overview"])

@router.get("/stats", response_model=Dict[str, Any])
def get_overview_statistics(db: Session = Depends(get_db)):
    """Computes comprehensive dashboard telemetry metrics directly from database."""
    total_agents = db.query(AgentModel).count()
    total_events = db.query(SecurityEventModel).count()
    
    # Distinct sessions
    distinct_sessions = db.query(func.count(func.distinct(SecurityEventModel.session_id))).scalar() or 0

    # Blocked operations
    blocked_count = db.query(SecurityEventModel).filter(
        SecurityEventModel.execution_status == "BLOCKED"
    ).count()

    # High / Critical incidents
    high_critical_count = db.query(IncidentModel).filter(
        IncidentModel.severity.in_(["HIGH", "CRITICAL"])
    ).count()

    total_incidents = db.query(IncidentModel).count()

    # Recent incidents
    recent_incidents = db.query(IncidentModel).order_by(
        IncidentModel.created_at.desc()
    ).limit(5).all()

    # Recent events
    recent_events = db.query(SecurityEventModel).order_by(
        SecurityEventModel.timestamp.desc()
    ).limit(10).all()

    # Policy decision distribution
    decisions = db.query(
        SecurityEventModel.policy_decision,
        func.count(SecurityEventModel.event_id)
    ).group_by(SecurityEventModel.policy_decision).all()
    decision_map = {d[0]: d[1] for d in decisions}

    # Threat category distribution
    categories = db.query(
        IncidentModel.primary_threat_category,
        func.count(IncidentModel.incident_id)
    ).group_by(IncidentModel.primary_threat_category).all()
    category_map = {c[0]: c[1] for c in categories}

    return {
        "monitored_agents_count": total_agents,
        "total_sessions_count": distinct_sessions,
        "security_events_count": total_events,
        "blocked_operations_count": blocked_count,
        "high_critical_alerts_count": high_critical_count,
        "total_incidents_count": total_incidents,
        "decision_distribution": decision_map,
        "threat_category_distribution": category_map,
        "recent_incidents": [IncidentResponse.model_validate(inc) for inc in recent_incidents],
        "recent_events": [SecurityEventResponse.model_validate(e) for e in recent_events]
    }
