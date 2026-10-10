export interface PolicyManifest {
  policy_id: string;
  agent_id: string;
  version: string;
  allowed_tools: string[];
  allowed_paths: string[];
  denied_paths: string[];
  allowed_network_domains: string[];
  allowed_operations: string[];
  require_approval_operations: string[];
  max_denial_threshold: number;
}

export interface Agent {
  agent_id: string;
  name: string;
  role: string;
  description?: string;
  authorized_objective: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  policy?: PolicyManifest;
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  task_id: string;
  action_type: string;
  tool_name?: string;
  resource?: string;
  requested_operation?: string;
  parameters: Record<string, any>;
  policy_decision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'NONE';
  execution_status: 'EXECUTED' | 'BLOCKED' | 'PENDING' | 'FAILED';
  execution_output?: string;
  risk_indicators: string[];
  source_of_input: string;
  related_incident_id?: string;
}

export interface Incident {
  incident_id: string;
  session_id: string;
  agent_id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  primary_threat_category: string;
  summary: string;
  confidence_score: number;
  triggering_event_id: string;
  evidence_event_ids: string[];
  detection_engines: string[];
  mitigation_status: string;
  recommendation?: string;
  investigation_report?: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentDetail extends Incident {
  timeline_events: SecurityEvent[];
}

export interface OverviewStats {
  monitored_agents_count: number;
  total_sessions_count: number;
  security_events_count: number;
  blocked_operations_count: number;
  high_critical_alerts_count: number;
  total_incidents_count: number;
  decision_distribution: Record<string, number>;
  threat_category_distribution: Record<string, number>;
  recent_incidents: Incident[];
  recent_events: SecurityEvent[];
}

export interface SimulationScenario {
  scenario_id: string;
  name: string;
  category: string;
  is_attack: boolean;
  is_unseen: boolean;
  agent_id: string;
  description: string;
  step_count: number;
}

export interface SimulationStepResult {
  step_number: number;
  tool: string;
  params: Record<string, any>;
  policy_decision: string;
  execution_status: string;
  decision_reason: string;
  risk_indicators: string[];
  event_id: string;
}

export interface SimulationRunResult {
  scenario_id: string;
  name: string;
  category: string;
  is_attack: boolean;
  is_unseen: boolean;
  session_id: string;
  total_steps: number;
  executed_steps: number;
  blocked_steps: number;
  gateway_protected_safely: boolean;
  incidents_created: string[];
  execution_time_ms: number;
  step_results: SimulationStepResult[];
}

export interface DetectorMetrics {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  fnr: number;
  avg_latency_ms: number;
}

export interface BenchmarkSummary {
  timestamp: string;
  total_scenarios: number;
  benign_count: number;
  attack_count: number;
  unseen_count: number;
  blocking_effectiveness: number;
  comparison: {
    rule: DetectorMetrics;
    sequence: DetectorMetrics;
    ml: DetectorMetrics;
    combined: DetectorMetrics;
  };
  unseen_accuracy: {
    rule: number;
    sequence: number;
    ml: number;
    combined: number;
  };
  scenario_results: any[];
}

export interface ThreatGraphNode {
  id: string;
  label: string;
  type: 'INCIDENT' | 'THREAT_CATEGORY';
  severity?: string;
  category?: string;
  agent_id?: string;
}

export interface ThreatGraphEdge {
  source: string;
  target: string;
  relationship: string;
  weight: number;
  shared_targets?: string[];
  attribution_disclaimer?: string;
}

export interface ThreatGraphData {
  total_nodes: number;
  total_edges: number;
  nodes: ThreatGraphNode[];
  edges: ThreatGraphEdge[];
}
