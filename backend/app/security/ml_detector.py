"""
Machine Learning Anomaly Detection Engine.
Extracts engineered behavioral feature vectors from agent session event logs.
Employs Isolation Forest / Multivariate Statistical Outlier Detection to discover
novel and out-of-distribution attack patterns without hardcoded signatures.
"""

from typing import List, Dict, Any, Tuple, Optional
import math
import json
from pathlib import Path
from datetime import datetime, timezone
from app.models.event import SecurityEventModel
from app.core.config import settings

FEATURE_NAMES = [
    "total_calls",
    "denial_rate",
    "sensitive_resource_count",
    "tool_diversity",
    "network_ratio",
    "external_domain_count",
    "consecutive_denials",
    "traversal_count"
]

class MLAnomalyDetector:
    """Interpretable ML behavioral anomaly detector for agent sessions."""

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or settings.ml_model_dir
        self.baseline_stats: Dict[str, Dict[str, float]] = {
            "total_calls": {"mean": 3.2, "std": 1.4},
            "denial_rate": {"mean": 0.02, "std": 0.05},
            "sensitive_resource_count": {"mean": 0.0, "std": 0.01},
            "tool_diversity": {"mean": 0.65, "std": 0.20},
            "network_ratio": {"mean": 0.08, "std": 0.12},
            "external_domain_count": {"mean": 0.0, "std": 0.05},
            "consecutive_denials": {"mean": 0.05, "std": 0.15},
            "traversal_count": {"mean": 0.0, "std": 0.01}
        }
        self.threshold: float = 2.35  # Composite Mahalanobis / Z-score threshold
        self.sklearn_model = None
        self._try_load_sklearn()

    def _try_load_sklearn(self):
        """Attempts to load scikit-learn IsolationForest if library is present."""
        try:
            from sklearn.ensemble import IsolationForest
            self.sklearn_model = IsolationForest(
                n_estimators=100,
                contamination=0.10,
                random_state=42
            )
            # Pre-fit on synthetic benign baseline matrix
            benign_matrix = [
                [2.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0],
                [3.0, 0.0, 0.0, 0.66, 0.0, 0.0, 0.0, 0.0],
                [4.0, 0.0, 0.0, 0.75, 0.25, 0.0, 0.0, 0.0],
                [3.0, 0.0, 0.0, 0.66, 0.0, 0.0, 0.0, 0.0],
                [2.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0],
                [5.0, 0.0, 0.0, 0.6, 0.2, 0.0, 0.0, 0.0],
            ]
            self.sklearn_model.fit(benign_matrix)
        except Exception:
            self.sklearn_model = None

    def extract_features(self, events: List[SecurityEventModel]) -> Dict[str, float]:
        """Engineers numerical behavioral features from an event stream."""
        if not events:
            return {f: 0.0 for f in FEATURE_NAMES}

        total = len(events)
        denied = sum(1 for e in events if e.policy_decision == "DENY" or e.execution_status == "BLOCKED")
        tools = len(set(e.tool_name for e in events if e.tool_name))
        
        sensitive_count = 0
        network_count = 0
        ext_domains = set()
        traversals = 0

        # Calculate max consecutive denials
        max_consec = 0
        curr_consec = 0

        for e in events:
            inds = e.risk_indicators or []
            if any("CREDENTIAL" in i or "HONEYTOKEN" in i for i in inds):
                sensitive_count += 1
            if "DIRECTORY_TRAVERSAL" in inds or "SANDBOX_ESCAPE" in inds:
                traversals += 1
            if e.requested_operation == "NETWORK_CALL" or e.tool_name in ["browser_open", "mock_api_request"]:
                network_count += 1
                if e.resource:
                    ext_domains.add(e.resource.split("/")[0])

            if e.policy_decision == "DENY":
                curr_consec += 1
                if curr_consec > max_consec:
                    max_consec = curr_consec
            else:
                curr_consec = 0

        return {
            "total_calls": float(total),
            "denial_rate": round(denied / total, 3),
            "sensitive_resource_count": float(sensitive_count),
            "tool_diversity": round(tools / max(1, total), 3),
            "network_ratio": round(network_count / max(1, total), 3),
            "external_domain_count": float(len(ext_domains)),
            "consecutive_denials": float(max_consec),
            "traversal_count": float(traversals)
        }

    def evaluate_event(
        self,
        current_event: SecurityEventModel,
        prior_events: List[SecurityEventModel]
    ) -> Tuple[bool, float]:
        """
        Evaluates whether the session is an anomaly.
        Returns: (is_anomaly: bool, anomaly_score: float)
        """
        full_events = list(prior_events) + [current_event]
        features = self.extract_features(full_events)

        # 1. If sklearn IsolationForest is available, use it
        if self.sklearn_model:
            feat_vector = [[features[name] for name in FEATURE_NAMES]]
            try:
                raw_score = self.sklearn_model.decision_function(feat_vector)[0]
                is_anomaly = bool(self.sklearn_model.predict(feat_vector)[0] == -1)
                # Normalize score to [0.0, 1.0] where higher is more anomalous
                norm_score = max(0.0, min(1.0, 0.5 - (raw_score * 2.0)))
                return (is_anomaly, round(norm_score, 3))
            except Exception:
                pass

        # 2. Interpretable Statistical Z-Score / Deviance Fallback
        deviance_sum = 0.0
        for feat_name, val in features.items():
            base = self.baseline_stats.get(feat_name, {"mean": 0.0, "std": 1.0})
            mean = base["mean"]
            std = max(0.01, base["std"])
            z = max(0.0, (val - mean) / std)
            deviance_sum += (z * z)

        composite_score = math.sqrt(deviance_sum)
        normalized_anomaly_score = round(min(1.0, composite_score / 6.0), 3)
        is_anomaly = composite_score >= self.threshold

        return (is_anomaly, normalized_anomaly_score)

    def explain_anomaly(self, features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Provides feature contribution ranking for why an anomaly was flagged."""
        contributions = []
        for feat, val in features.items():
            base = self.baseline_stats.get(feat, {"mean": 0.0, "std": 1.0})
            diff = val - base["mean"]
            if diff > 0.05:
                contributions.append({
                    "feature": feat,
                    "observed_value": val,
                    "baseline_mean": base["mean"],
                    "deviation_ratio": round(val / max(0.01, base["mean"]), 2)
                })
        contributions.sort(key=lambda x: x["deviation_ratio"], reverse=True)
        return contributions

ml_detector = MLAnomalyDetector()
