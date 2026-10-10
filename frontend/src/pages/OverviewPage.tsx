import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Bot,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ArrowRight,
  TrendingUp,
  Cpu
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, PieChart, Pie } from 'recharts';
import { api } from '../services/api';
import { OverviewStats, Incident } from '../types';

interface OverviewPageProps {
  onNavigateToIncident: (incidentId: string) => void;
  onNavigateToLiveMonitor: () => void;
}

const COLORS = ['#10b981', '#ef4444', '#f59e0b', '#38bdf8', '#a855f7'];

export const OverviewPage: React.FC<OverviewPageProps> = ({
  onNavigateToIncident,
  onNavigateToLiveMonitor
}) => {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      const data = await api.getOverviewStats();
      setStats(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to SecOps backend.');
    } finally {
      setLoading(false);
    }
  };

  if (loading && !stats) {
    return (
      <div className="p-8 flex items-center justify-center space-x-3 text-slate-400">
        <Activity className="w-5 h-5 animate-spin text-sky-400" />
        <span className="font-mono text-sm">Aggregating live agent telemetry...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8">
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm">
          <p className="font-bold mb-1">Backend Connection Notice</p>
          <p>{error}</p>
          <button
            onClick={loadStats}
            className="mt-3 px-3 py-1.5 bg-rose-600/30 hover:bg-rose-600/50 rounded text-xs font-mono"
          >
            Retry Sync
          </button>
        </div>
      </div>
    );
  }

  const decisionData = Object.entries(stats?.decision_distribution || {}).map(([key, val]) => ({
    name: key,
    value: val
  }));

  const categoryData = Object.entries(stats?.threat_category_distribution || {}).map(([key, val]) => ({
    name: key.replace(/_/g, ' '),
    count: val
  }));

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
            <span>SECOPS SECURITY POSTURE</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time policy enforcement, behavioral monitoring, and threat detection across monitored agents.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={onNavigateToLiveMonitor}
            className="px-3.5 py-1.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400 hover:bg-sky-500/20 text-xs font-mono font-medium flex items-center space-x-2 transition-all"
          >
            <span>VIEW LIVE AUDIT STREAM</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Metric Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Monitored Agents */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>MONITORED AGENTS</span>
            <Bot className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{stats?.monitored_agents_count ?? 0}</div>
          <div className="text-[11px] text-slate-400">Least-privilege policy manifests active</div>
        </div>

        {/* Security Events */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>INTERCEPTED CALLS</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{stats?.security_events_count ?? 0}</div>
          <div className="text-[11px] text-slate-400">
            Across {stats?.total_sessions_count ?? 0} unique agent execution sessions
          </div>
        </div>

        {/* Blocked Dangerous Actions */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>PREVENTED ACTIONS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">{stats?.blocked_operations_count ?? 0}</div>
          <div className="text-[11px] text-rose-300/80">Blocked at gateway prior to execution</div>
          <div className="absolute top-0 right-0 w-16 h-16 bg-rose-500/5 rounded-full blur-xl pointer-events-none"></div>
        </div>

        {/* Active High/Critical Alerts */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>HIGH/CRIT ALERTS</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{stats?.high_critical_alerts_count ?? 0}</div>
          <div className="text-[11px] text-slate-400">Total Incidents: {stats?.total_incidents_count ?? 0}</div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Policy Decisions Distribution */}
        <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              GATEWAY ENFORCEMENT BREAKDOWN
            </h3>
            <span className="text-[10px] font-mono text-slate-400">ALLOW vs DENY vs APPROVAL</span>
          </div>

          <div className="h-56">
            {decisionData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={decisionData} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <XAxis type="number" stroke="#475569" fontSize={11} />
                  <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={80} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc', fontSize: '12px' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {decisionData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.name === 'ALLOW' ? '#10b981' : entry.name === 'DENY' ? '#ef4444' : '#f59e0b'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-400 text-xs font-mono">
                No telemetry recorded yet. Run a simulation scenario.
              </div>
            )}
          </div>
        </div>

        {/* Threat Categories Distribution */}
        <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              DETECTED THREAT CATEGORIES
            </h3>
            <span className="text-[10px] font-mono text-slate-400">CLASSIFICATION PROFILES</span>
          </div>

          <div className="h-56">
            {categoryData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData} margin={{ left: 0, right: 20, bottom: 20 }}>
                  <XAxis
                    dataKey="name"
                    stroke="#475569"
                    fontSize={10}
                    interval={0}
                    angle={-15}
                    textAnchor="end"
                  />
                  <YAxis stroke="#475569" fontSize={11} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc', fontSize: '12px' }}
                  />
                  <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-400 text-xs font-mono">
                No security incidents flagged yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Incidents Table */}
      <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <span>RECENT SECURITY INCIDENTS</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
              {stats?.recent_incidents?.length ?? 0} RECENT
            </span>
          </h3>
          <span className="text-xs text-slate-400">Click row to investigate causal timeline</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 font-mono text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-3">INCIDENT TITLE</th>
                <th className="py-2.5 px-3">AGENT ID</th>
                <th className="py-2.5 px-3">CATEGORY</th>
                <th className="py-2.5 px-3">SEVERITY</th>
                <th className="py-2.5 px-3">STATUS</th>
                <th className="py-2.5 px-3">MITIGATION</th>
                <th className="py-2.5 px-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans text-slate-300">
              {stats?.recent_incidents && stats.recent_incidents.length > 0 ? (
                stats.recent_incidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => onNavigateToIncident(inc.incident_id)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3 font-medium text-slate-100 flex items-center space-x-2 truncate max-w-xs">
                      <span className="truncate">{inc.title}</span>
                    </td>
                    <td className="py-3 px-3 font-mono text-sky-400 text-[11px]">{inc.agent_id}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">
                        {inc.primary_threat_category}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          inc.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : inc.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-slate-400">{inc.status}</td>
                    <td className="py-3 px-3">
                      <span className="inline-flex items-center space-x-1 text-emerald-400 font-mono text-[10px]">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>{inc.mitigation_status}</span>
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className="text-sky-400 hover:text-sky-300 font-mono text-[11px] flex items-center justify-end space-x-1">
                        <span>Investigate</span>
                        <ArrowRight className="w-3 h-3" />
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400 font-mono text-xs">
                    No security incidents recorded. Visit the Simulation Lab to execute an attack scenario.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
