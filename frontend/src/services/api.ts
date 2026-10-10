import {
  OverviewStats,
  Agent,
  SecurityEvent,
  Incident,
  IncidentDetail,
  SimulationScenario,
  SimulationRunResult,
  BenchmarkSummary,
  ThreatGraphData
} from '../types';

const API_BASE = '/api/v1';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {})
    },
    ...options
  });
  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`API Error ${res.status}: ${errorBody || res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Overview
  getOverviewStats: (): Promise<OverviewStats> => fetchJson<OverviewStats>('/overview/stats'),

  // Agents
  getAgents: (): Promise<Agent[]> => fetchJson<Agent[]>('/agents'),
  getAgent: (agentId: string): Promise<Agent> => fetchJson<Agent>(`/agents/${agentId}`),

  // Events
  getEvents: (params?: {
    session_id?: string;
    agent_id?: string;
    policy_decision?: string;
    execution_status?: string;
    limit?: number;
  }): Promise<SecurityEvent[]> => {
    const query = new URLSearchParams();
    if (params?.session_id) query.append('session_id', params.session_id);
    if (params?.agent_id) query.append('agent_id', params.agent_id);
    if (params?.policy_decision) query.append('policy_decision', params.policy_decision);
    if (params?.execution_status) query.append('execution_status', params.execution_status);
    if (params?.limit) query.append('limit', params.limit.toString());
    const qStr = query.toString() ? `?${query.toString()}` : '';
    return fetchJson<SecurityEvent[]>(`/events${qStr}`);
  },

  // Incidents
  getIncidents: (params?: { severity?: string; status?: string }): Promise<Incident[]> => {
    const query = new URLSearchParams();
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    const qStr = query.toString() ? `?${query.toString()}` : '';
    return fetchJson<Incident[]>(`/incidents${qStr}`);
  },
  getIncidentDetail: (incidentId: string): Promise<IncidentDetail> =>
    fetchJson<IncidentDetail>(`/incidents/${incidentId}`),
  investigateIncident: (incidentId: string, provider: string = 'offline'): Promise<{ status: string; report: string }> =>
    fetchJson<{ status: string; report: string }>(`/incidents/${incidentId}/investigate`, {
      method: 'POST',
      body: JSON.stringify({ provider })
    }),
  containIncident: (incidentId: string): Promise<{ status: string; message: string }> =>
    fetchJson<{ status: string; message: string }>(`/incidents/${incidentId}/contain`, {
      method: 'POST'
    }),

  // Simulations
  getScenarios: (): Promise<SimulationScenario[]> => fetchJson<SimulationScenario[]>('/simulations/scenarios'),
  runSimulation: (scenarioId: string): Promise<SimulationRunResult> =>
    fetchJson<SimulationRunResult>(`/simulations/run/${scenarioId}`, {
      method: 'POST'
    }),

  // Evaluation
  getEvaluationResults: (): Promise<BenchmarkSummary> => fetchJson<BenchmarkSummary>('/evaluation/results'),
  runBenchmark: (): Promise<BenchmarkSummary> =>
    fetchJson<BenchmarkSummary>('/evaluation/run-benchmark', {
      method: 'POST'
    }),

  // Threat Intel
  getThreatGraph: (): Promise<ThreatGraphData> => fetchJson<ThreatGraphData>('/threat-intel/graph')
};
