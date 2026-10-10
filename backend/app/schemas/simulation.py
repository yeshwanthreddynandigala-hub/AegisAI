"""
Pydantic Schemas for Attack Simulation Lab & Evaluation.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class SimulationScenario(BaseModel):
    scenario_id: str
    name: str
    category: str  # BENIGN, PROMPT_INJECTION, PRIVILEGE_ESCALATION, EXFILTRATION, ANOMALOUS_SEQUENCE, UNSEEN_ZERO_DAY
    description: str
    agent_id: str
    task_objective: str
    payload_type: str
    expected_outcome: str  # ALLOWED, BLOCKED_POLICY, DETECTED_ANOMALY, DETECTED_SEQUENCE
    steps: List[Dict[str, Any]] = Field(default_factory=list)

class SimulationRunRequest(BaseModel):
    scenario_id: str
    custom_overrides: Optional[Dict[str, Any]] = None

class SimulationRunResult(BaseModel):
    scenario_id: str
    scenario_name: str
    category: str
    session_id: str
    status: str  # SUCCESS_SAFE, ATTACK_BLOCKED, ATTACK_DETECTED, EXECUTION_ERROR
    total_steps: int
    executed_steps: int
    blocked_steps: int
    incidents_generated: int
    incident_ids: List[str] = Field(default_factory=list)
    gateway_blocked_safely: bool
    detection_methods_fired: List[str] = Field(default_factory=list)
    execution_time_ms: float
    log_summary: str

class BenchmarkEvaluationSummary(BaseModel):
    total_scenarios_evaluated: int
    benign_scenarios_count: int
    attack_scenarios_count: int
    unseen_scenarios_count: int
    
    # Metrics per detector
    rule_precision: float
    rule_recall: float
    rule_f1: float
    rule_fpr: float
    rule_fnr: float
    
    sequence_precision: float
    sequence_recall: float
    sequence_f1: float
    sequence_fpr: float
    sequence_fnr: float

    ml_precision: float
    ml_recall: float
    ml_f1: float
    ml_fpr: float
    ml_fnr: float

    combined_precision: float
    combined_recall: float
    combined_f1: float
    combined_fpr: float
    combined_fnr: float

    blocking_effectiveness: float
    avg_detection_latency_ms: float
    confusion_matrix: Dict[str, Dict[str, int]]
