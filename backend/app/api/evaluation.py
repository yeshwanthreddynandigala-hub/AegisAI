"""
API Router: Evaluation Center & Research Benchmarks.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
import json

from app.core.database import get_db
from app.evaluation.benchmark_runner import benchmark_runner
from app.core.config import settings
from app.models.user import UserModel
from app.api.deps import get_current_user, require_admin

router = APIRouter(prefix="/evaluation", tags=["Evaluation"])

@router.get("/results", response_model=Dict[str, Any])
def get_evaluation_results(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """
    Returns the most recent empirical evaluation benchmark metrics.
    If no prior benchmark exists, runs an initial benchmark dynamically.
    """
    out_file = settings.base_dir / "data" / "latest_benchmark.json"
    if out_file.exists():
        try:
            return json.loads(out_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Run benchmark if not cached
    return benchmark_runner.run_benchmark(db=db)

@router.post("/run-benchmark", response_model=Dict[str, Any])
def execute_benchmark(db: Session = Depends(get_db), admin_user: UserModel = Depends(require_admin)):
    """
    Executes all scenarios across Rule, Sequence, ML Anomaly, and Combined detectors (Admin privilege required).
    Measures Precision, Recall, F1, FPR, FNR, Latency, and Blocking Effectiveness.
    """
    return benchmark_runner.run_benchmark(db=db)
