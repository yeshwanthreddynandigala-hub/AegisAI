from app.security.policy_engine import policy_engine, PolicyEngine, PolicyDecisionResult
from app.security.rule_detector import rule_detector, RuleBasedDetector, TriggeredRule
from app.security.sequence_detector import sequence_detector, BehavioralSequenceDetector
from app.security.ml_detector import ml_detector, MLAnomalyDetector
from app.security.gateway import gateway, ToolExecutionGateway
from app.security.correlation_engine import correlation_engine, IncidentCorrelationEngine

# Connect detectors to correlation engine and gateway
correlation_engine.set_detectors(sequence_detector=sequence_detector, ml_detector=ml_detector)
gateway.set_correlation_engine(correlation_engine)

__all__ = [
    "policy_engine",
    "PolicyEngine",
    "PolicyDecisionResult",
    "rule_detector",
    "RuleBasedDetector",
    "TriggeredRule",
    "sequence_detector",
    "BehavioralSequenceDetector",
    "ml_detector",
    "MLAnomalyDetector",
    "gateway",
    "ToolExecutionGateway",
    "correlation_engine",
    "IncidentCorrelationEngine"
]
