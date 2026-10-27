"""
API Router: Attack Simulation Lab.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import time
import uuid

from app.core.database import get_db
from app.evaluation.scenarios import SCENARIO_CATALOG
from app.evaluation.benchmark_runner import _ensure_benchmark_agents
from app.models.user import UserModel
from app.schemas.event import ToolCallRequest
from app.security.gateway import gateway
from app.api.deps import get_current_user

router = APIRouter(prefix="/simulations", tags=["Simulations"])

@router.get("/scenarios", response_model=List[Dict[str, Any]])
def list_scenarios(current_user: UserModel = Depends(get_current_user)):
    """Returns available simulation lab scenarios."""
    return [
        {
            "scenario_id": s["scenario_id"],
            "name": s["name"],
            "category": s["category"],
            "is_attack": s["is_attack"],
            "is_unseen": s.get("is_unseen", False),
            "agent_id": s["agent_id"],
            "description": s["description"],
            "step_count": len(s["steps"])
        }
        for s in SCENARIO_CATALOG
    ]

@router.post("/run/{scenario_id}")
def run_simulation_scenario(scenario_id: str, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """
    Executes a controlled test scenario live against the Gateway and security pipeline.
    Returns real-time execution results, policy blocks, and created incidents.
    """
    scenario = next((s for s in SCENARIO_CATALOG if s["scenario_id"] == scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    _ensure_benchmark_agents(db)

    session_id = f"sim_{uuid.uuid4().hex[:10]}"
    task_id = f"task_{scenario['scenario_id']}"

    t_start = time.perf_counter()
    step_results = []
    blocked_count = 0
    executed_count = 0
    incidents_created = []

    for idx, step in enumerate(scenario["steps"], 1):
        req = ToolCallRequest(
            agent_id=scenario["agent_id"],
            session_id=session_id,
            task_id=task_id,
            tool_name=step["tool"],
            parameters=step["params"],
            source_of_input=step.get("source", "DIRECT_AGENT")
        )

        resp = gateway.dispatch_tool_call(db=db, request=req)

        if resp.execution_status == "BLOCKED":
            blocked_count += 1
        elif resp.execution_status == "EXECUTED":
            executed_count += 1

        if resp.incident_created and resp.incident_id:
            incidents_created.append(resp.incident_id)

        step_results.append({
            "step_number": idx,
            "tool": step["tool"],
            "params": step["params"],
            "policy_decision": resp.policy_decision,
            "execution_status": resp.execution_status,
            "decision_reason": resp.decision_reason,
            "risk_indicators": resp.risk_indicators,
            "event_id": resp.event_id
        })

    elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    return {
        "scenario_id": scenario["scenario_id"],
        "name": scenario["name"],
        "category": scenario["category"],
        "is_attack": scenario["is_attack"],
        "is_unseen": scenario.get("is_unseen", False),
        "session_id": session_id,
        "total_steps": len(scenario["steps"]),
        "executed_steps": executed_count,
        "blocked_steps": blocked_count,
        "gateway_protected_safely": (blocked_count > 0) if scenario["is_attack"] else (blocked_count == 0),
        "incidents_created": list(set(incidents_created)),
        "execution_time_ms": round(elapsed_ms, 2),
        "step_results": step_results
    }
