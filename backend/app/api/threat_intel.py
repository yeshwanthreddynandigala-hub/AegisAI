"""
API Router: Threat Intelligence & Incident Correlation Graph.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.core.database import get_db
from app.investigation.threat_intel import threat_correlator

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

@router.get("/graph", response_model=Dict[str, Any])
def get_threat_graph(db: Session = Depends(get_db)):
    """
    Returns graph nodes and edges connecting incidents via shared behavioral patterns,
    targeted resources, and attack vectors.
    """
    return threat_correlator.build_threat_graph(db=db)
