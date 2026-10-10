"""
Empirical Benchmark and Evaluation Runner.
Executes test scenarios through the Gateway, records detection metrics,
and computes Precision, Recall, F1, FPR, FNR, Latency, and Blocking Effectiveness.
Never fabricates data: strictly computes metrics from actual execution runs.
"""

from typing import Dict, Any, List
import time
import json
import uuid
from pathlib import Path
from sqlalchemy.orm import Session

from app.evaluation.scenarios import SCENARIO_CATALOG
from app.models.agent import AgentModel, PolicyManifestModel
from app.models.event import SecurityEventModel
from app.security.gateway import gateway
from app.security.rule_detector import rule_detector
from app.security.sequence_detector import sequence_detector
from app.security.ml_detector import ml_detector
from app.schemas.event import ToolCallRequest
from app.core.config import settings

def _ensure_benchmark_agents(db: Session):
    """Ensures test agent identities and policies exist in DB."""
    # 1. Researcher agent
    if not db.query(AgentModel).filter(AgentModel.agent_id == "agent_researcher_001").first():
        agent1 = AgentModel(
            agent_id="agent_researcher_001",
            name="Research Analyst Agent",
            role="Document Analyst",
            authorized_objective="Summarize public annual reports and calculate basic operational statistics."
        )
        policy1 = PolicyManifestModel(
            policy_id=str(uuid.uuid4()),
            agent_id="agent_researcher_001",
            allowed_tools=["document_reader", "calculator", "browser_search"],
            allowed_paths=["public/*"],
            denied_paths=["credentials/*", "private/*"],
            allowed_network_domains=["api.internal.mock"],
            allowed_operations=["READ", "CALCULATE", "SEARCH"],
            require_approval_operations=["WRITE"],
            max_denial_threshold=3
        )
        db.add(agent1)
        db.add(policy1)

    # 2. Database analyst agent
    if not db.query(AgentModel).filter(AgentModel.agent_id == "agent_analyst_002").first():
        agent2 = AgentModel(
            agent_id="agent_analyst_002",
            name="Database Analyst Agent",
            role="Data Analyst",
            authorized_objective="Query public product tables and generate pricing aggregations."
        )
        policy2 = PolicyManifestModel(
            policy_id=str(uuid.uuid4()),
            agent_id="agent_analyst_002",
            allowed_tools=["database_query", "calculator"],
            allowed_paths=["public/*"],
            denied_paths=["credentials/*", "private/*"],
            allowed_network_domains=[],
            allowed_operations=["DB_QUERY", "CALCULATE"],
            require_approval_operations=["WRITE", "DELETE"],
            max_denial_threshold=3
        )
        db.add(agent2)
        db.add(policy2)

    db.commit()

class BenchmarkRunner:
    """Executes benchmark suites and calculates empirical research statistics."""

    def run_benchmark(self, db: Session) -> Dict[str, Any]:
        """Runs the entire scenario catalog and computes comparative metrics."""
        _ensure_benchmark_agents(db)

        results_by_scenario = []

        total_scenarios = len(SCENARIO_CATALOG)
        benign_count = sum(1 for s in SCENARIO_CATALOG if not s["is_attack"])
        attack_count = sum(1 for s in SCENARIO_CATALOG if s["is_attack"])
        unseen_count = sum(1 for s in SCENARIO_CATALOG if s.get("is_unseen", False))

        # Metrics accumulator for: rule, sequence, ml, combined
        detector_stats = {
            "rule": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies_ms": []},
            "sequence": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies_ms": []},
            "ml": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies_ms": []},
            "combined": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies_ms": []}
        }

        unseen_detector_stats = {
            "rule": {"detected": 0, "total": unseen_count},
            "sequence": {"detected": 0, "total": unseen_count},
            "ml": {"detected": 0, "total": unseen_count},
            "combined": {"detected": 0, "total": unseen_count}
        }

        blocked_attacks = 0

        for scenario in SCENARIO_CATALOG:
            session_id = f"bench_{uuid.uuid4().hex[:10]}"
            task_id = f"bench_task_{scenario['scenario_id']}"
            is_attack = scenario["is_attack"]
            is_unseen = scenario.get("is_unseen", False)

            scenario_rule_fired = False
            scenario_seq_fired = False
            scenario_ml_fired = False
            scenario_blocked = False

            step_latencies = []

            for step in scenario["steps"]:
                t_start = time.perf_counter()

                req = ToolCallRequest(
                    agent_id=scenario["agent_id"],
                    session_id=session_id,
                    task_id=task_id,
                    tool_name=step["tool"],
                    parameters=step["params"],
                    source_of_input=step.get("source", "DIRECT_AGENT")
                )

                resp = gateway.dispatch_tool_call(db=db, request=req)
                t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                step_latencies.append(t_elapsed_ms)

                if resp.execution_status == "BLOCKED":
                    scenario_blocked = True

                # Evaluate individual detector responses on the event
                evt = db.query(SecurityEventModel).filter(SecurityEventModel.event_id == resp.event_id).first()
                prior = db.query(SecurityEventModel).filter(
                    SecurityEventModel.session_id == session_id,
                    SecurityEventModel.event_id != resp.event_id
                ).all()

                if evt:
                    if rule_detector.evaluate_event(evt, prior):
                        scenario_rule_fired = True
                    if sequence_detector.evaluate_sequence(evt, prior):
                        scenario_seq_fired = True
                    is_anom, _ = ml_detector.evaluate_event(evt, prior)
                    if is_anom:
                        scenario_ml_fired = True

            scenario_combined_fired = (scenario_rule_fired or scenario_seq_fired or scenario_ml_fired)

            avg_scenario_latency = sum(step_latencies) / max(1, len(step_latencies))

            # Record stats per detector
            for det_name, fired in [
                ("rule", scenario_rule_fired),
                ("sequence", scenario_seq_fired),
                ("ml", scenario_ml_fired),
                ("combined", scenario_combined_fired)
            ]:
                stat = detector_stats[det_name]
                stat["latencies_ms"].append(avg_scenario_latency)
                if is_attack:
                    if fired:
                        stat["tp"] += 1
                        if is_unseen:
                            unseen_detector_stats[det_name]["detected"] += 1
                    else:
                        stat["fn"] += 1
                else:
                    if fired:
                        stat["fp"] += 1
                    else:
                        stat["tn"] += 1

            if is_attack and scenario_blocked:
                blocked_attacks += 1

            results_by_scenario.append({
                "scenario_id": scenario["scenario_id"],
                "name": scenario["name"],
                "category": scenario["category"],
                "is_attack": is_attack,
                "is_unseen": is_unseen,
                "session_id": session_id,
                "blocked": scenario_blocked,
                "rule_fired": scenario_rule_fired,
                "sequence_fired": scenario_seq_fired,
                "ml_fired": scenario_ml_fired,
                "combined_fired": scenario_combined_fired,
                "avg_latency_ms": round(avg_scenario_latency, 2)
            })

        # Calculate comparative metrics
        def _calc_metrics(st: Dict[str, Any]) -> Dict[str, float]:
            tp, fp, tn, fn = st["tp"], st["fp"], st["tn"], st["fn"]
            precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
            recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
            f1 = round((2 * precision * recall) / (precision + recall), 3) if (precision + recall) > 0 else 0.0
            fpr = round(fp / (fp + tn), 3) if (fp + tn) > 0 else 0.0
            fnr = round(fn / (fn + tp), 3) if (fn + tp) > 0 else 0.0
            avg_lat = round(sum(st["latencies_ms"]) / max(1, len(st["latencies_ms"])), 2)
            return {
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "fpr": fpr,
                "fnr": fnr,
                "avg_latency_ms": avg_lat
            }

        comparison = {name: _calc_metrics(st) for name, st in detector_stats.items()}
        blocking_effectiveness = round(blocked_attacks / max(1, attack_count), 3)

        summary_payload = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_scenarios": total_scenarios,
            "benign_count": benign_count,
            "attack_count": attack_count,
            "unseen_count": unseen_count,
            "blocking_effectiveness": blocking_effectiveness,
            "comparison": comparison,
            "unseen_accuracy": {
                name: round(u["detected"] / max(1, u["total"]), 3)
                for name, u in unseen_detector_stats.items()
            },
            "scenario_results": results_by_scenario
        }

        # Persist latest benchmark result to file for dashboard retrieval
        out_file = settings.base_dir / "data" / "latest_benchmark.json"
        out_file.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")

        return summary_payload

benchmark_runner = BenchmarkRunner()
