import {
  OverviewStats,
  Agent,
  SecurityEvent,
  Incident,
  IncidentDetail,
  SimulationScenario,
  SimulationRunResult,
  BenchmarkSummary,
  ThreatGraphData,
  User,
  TokenResponse,
  LoginPayload,
  RegisterPayload
} from '../types';

const API_BASE = '/api/v1';
const TOKEN_KEY = 'aegis_token';

let unauthorizedListeners: Array<() => void> = [];

export function onUnauthorized(callback: () => void): () => void {
  unauthorizedListeners.push(callback);
  return () => {
    unauthorizedListeners = unauthorizedListeners.filter(cb => cb !== callback);
  };
}

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string> || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers
  });

  if (res.status === 401 && !url.includes('/auth/login')) {
    // Stored token is invalid or expired
    setStoredToken(null);
    unauthorizedListeners.forEach(cb => cb());
  }

  if (!res.ok) {
    const errorBody = await res.text();
    let parsedMessage = errorBody;
    try {
      const parsed = JSON.parse(errorBody);
      if (parsed.detail) {
        parsedMessage = typeof parsed.detail === 'string' ? parsed.detail : JSON.stringify(parsed.detail);
      }
    } catch {
      // Keep raw body
    }
    throw new Error(`API Error ${res.status}: ${parsedMessage || res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Authentication & RBAC
  login: async (payload: LoginPayload): Promise<TokenResponse> => {
    const data = await fetchJson<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (data.access_token) {
      setStoredToken(data.access_token);
    }
    return data;
  },

  register: (payload: RegisterPayload): Promise<User> =>
    fetchJson<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload)
    }),

  getCurrentUser: (): Promise<User> => fetchJson<User>('/auth/me'),

  logout: (): void => {
    setStoredToken(null);
  },

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
