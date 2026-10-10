import React, { useEffect, useState } from 'react';
import {
  Terminal,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Eye,
  RefreshCw,
  FileCode
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityEvent } from '../types';

export const LiveMonitorPage: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Filters
  const [decisionFilter, setDecisionFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    fetchEvents();
  }, [decisionFilter, statusFilter]);

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const data = await api.getEvents({
        policy_decision: decisionFilter || undefined,
        execution_status: statusFilter || undefined,
        limit: 100
      });
      setEvents(data);
    } catch (err) {
      console.error('Failed to fetch events:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredEvents = events.filter((e) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.agent_id.toLowerCase().includes(q) ||
      (e.tool_name && e.tool_name.toLowerCase().includes(q)) ||
      (e.resource && e.resource.toLowerCase().includes(q)) ||
      e.session_id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Title & Stats */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-sky-400" />
            <span>LIVE AUDIT TELEMETRY MONITOR</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time chronological tool call requests intercepted by the zero-trust execution gateway.
          </p>
        </div>

        <button
          onClick={fetchEvents}
          disabled={loading}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 flex items-center space-x-2"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          <span>REFRESH LOGS</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-slate-900/80 p-3 rounded-xl border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by agent, tool, resource..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          {/* Decision Filter */}
          <div className="flex items-center space-x-1 text-xs font-mono">
            <span className="text-slate-500 text-[11px]">DECISION:</span>
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1 text-xs focus:outline-none focus:border-sky-500"
            >
              <option value="">ALL</option>
              <option value="ALLOW">ALLOW</option>
              <option value="DENY">DENY</option>
              <option value="REQUIRE_APPROVAL">REQUIRE APPROVAL</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center space-x-1 text-xs font-mono">
            <span className="text-slate-500 text-[11px]">STATUS:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1 text-xs focus:outline-none focus:border-sky-500"
            >
              <option value="">ALL</option>
              <option value="EXECUTED">EXECUTED</option>
              <option value="BLOCKED">BLOCKED</option>
              <option value="FAILED">FAILED</option>
            </select>
          </div>
        </div>
      </div>

      {/* Telemetry Table & Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Event List */}
        <div className={`rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden ${selectedEvent ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <div className="p-3 border-b border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>RECORDED TELEMETRY STREAM ({filteredEvents.length} EVENTS)</span>
            <span className="text-[10px] text-slate-500">SORT: CHRONOLOGICAL DESC</span>
          </div>

          <div className="overflow-x-auto max-h-[620px] overflow-y-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-950 border-b border-slate-800 text-[10px] font-mono text-slate-400 uppercase">
                <tr>
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">AGENT ID</th>
                  <th className="py-2.5 px-3">ACTION / TOOL</th>
                  <th className="py-2.5 px-3">TARGET RESOURCE</th>
                  <th className="py-2.5 px-3">DECISION</th>
                  <th className="py-2.5 px-3">STATUS</th>
                  <th className="py-2.5 px-3 text-right">VIEW</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300 text-[11px]">
                {filteredEvents.length > 0 ? (
                  filteredEvents.map((e) => {
                    const isSelected = selectedEvent?.event_id === e.event_id;
                    const isBlocked = e.policy_decision === 'DENY' || e.execution_status === 'BLOCKED';
                    return (
                      <tr
                        key={e.event_id}
                        onClick={() => setSelectedEvent(e)}
                        className={`hover:bg-slate-800/50 cursor-pointer transition-colors ${
                          isSelected ? 'bg-sky-500/10' : ''
                        }`}
                      >
                        <td className="py-2.5 px-3 text-slate-400 text-[10px] whitespace-nowrap">
                          {new Date(e.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 text-sky-400 font-semibold">{e.agent_id}</td>
                        <td className="py-2.5 px-3">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-200">
                            {e.tool_name || e.action_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate" title={e.resource}>
                          {e.resource || 'none'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              e.policy_decision === 'ALLOW'
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : e.policy_decision === 'DENY'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            }`}
                          >
                            {e.policy_decision}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-flex items-center space-x-1 text-[10px] ${
                              e.execution_status === 'EXECUTED'
                                ? 'text-emerald-400'
                                : e.execution_status === 'BLOCKED'
                                ? 'text-rose-400'
                                : 'text-slate-400'
                            }`}
                          >
                            {e.execution_status === 'EXECUTED' ? (
                              <CheckCircle2 className="w-3 h-3" />
                            ) : (
                              <XCircle className="w-3 h-3" />
                            )}
                            <span>{e.execution_status}</span>
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setSelectedEvent(e);
                            }}
                            className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-400 font-mono text-xs">
                      {loading ? 'Fetching telemetry events...' : 'No telemetry events match active filters.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Event Detail Inspector Drawer */}
        {selectedEvent && (
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 lg:col-span-1 h-fit sticky top-20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
                <FileCode className="w-4 h-4 text-sky-400" />
                <span>EVENT TELEMETRY INSPECTOR</span>
              </h3>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                CLOSE
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 text-[10px]">EVENT ID</span>
                <div className="text-slate-300 break-all bg-slate-950 p-1.5 rounded border border-slate-800 text-[11px]">
                  {selectedEvent.event_id}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500 text-[10px]">AGENT</span>
                  <div className="text-sky-400">{selectedEvent.agent_id}</div>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">TOOL</span>
                  <div className="text-slate-200">{selectedEvent.tool_name || 'N/A'}</div>
                </div>
              </div>

              <div>
                <span className="text-slate-500 text-[10px]">TARGET RESOURCE</span>
                <div className="text-slate-200 break-all bg-slate-950 p-1.5 rounded border border-slate-800 text-[11px]">
                  {selectedEvent.resource || 'None'}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500 text-[10px]">GATEWAY DECISION</span>
                  <div
                    className={`font-bold ${
                      selectedEvent.policy_decision === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'
                    }`}
                  >
                    {selectedEvent.policy_decision}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">STATUS</span>
                  <div className="text-slate-300">{selectedEvent.execution_status}</div>
                </div>
              </div>

              {selectedEvent.risk_indicators && selectedEvent.risk_indicators.length > 0 && (
                <div>
                  <span className="text-slate-500 text-[10px]">RISK INDICATORS</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedEvent.risk_indicators.map((ind, i) => (
                      <span
                        key={i}
                        className="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 text-[10px]"
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <span className="text-slate-500 text-[10px]">INVOCATION PARAMETERS</span>
                <pre className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] text-slate-300 max-h-32 overflow-y-auto">
                  {JSON.stringify(selectedEvent.parameters, null, 2)}
                </pre>
              </div>

              {selectedEvent.execution_output && (
                <div>
                  <span className="text-slate-500 text-[10px]">EXECUTION OUTPUT / GATEWAY REASON</span>
                  <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] text-slate-300 max-h-32 overflow-y-auto whitespace-pre-wrap">
                    {selectedEvent.execution_output}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
