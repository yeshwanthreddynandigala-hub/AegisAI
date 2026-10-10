import React, { useEffect, useState } from 'react';
import { Bot, Shield, CheckCircle, XCircle, AlertCircle, Lock, FileText, Globe } from 'lucide-react';
import { api } from '../services/api';
import { Agent } from '../types';

export const AgentExplorerPage: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    loadAgents();
  }, []);

  const loadAgents = async () => {
    try {
      setLoading(true);
      const data = await api.getAgents();
      setAgents(data);
      if (data.length > 0 && !selectedAgent) {
        setSelectedAgent(data[0]);
      }
    } catch (err) {
      console.error('Failed to load agents:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
          <Bot className="w-5 h-5 text-sky-400" />
          <span>AGENT IDENTITY & AUTHORIZATION EXPLORER</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Inspect provisioned AI agent identities, task objectives, and least-privilege security policy manifests.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent List */}
        <div className="space-y-3 lg:col-span-1">
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
            PROVISIONED AGENTS ({agents.length})
          </h2>

          <div className="space-y-2">
            {agents.map((ag) => {
              const isSelected = selectedAgent?.agent_id === ag.agent_id;
              return (
                <div
                  key={ag.agent_id}
                  onClick={() => setSelectedAgent(ag)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-sky-500/10 border-sky-500/40 text-white shadow-lg shadow-sky-950/20'
                      : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs font-bold text-sky-400">{ag.agent_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      ACTIVE
                    </span>
                  </div>
                  <h3 className="font-semibold text-sm text-slate-100">{ag.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">{ag.role}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Agent Details & Security Policy Manifest */}
        <div className="lg:col-span-2 space-y-6">
          {selectedAgent ? (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
              {/* Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center space-x-2">
                    <span>{selectedAgent.name}</span>
                    <span className="font-mono text-xs text-sky-400 font-normal">({selectedAgent.agent_id})</span>
                  </h2>
                  <div className="text-xs text-slate-400 mt-0.5">Role: {selectedAgent.role}</div>
                </div>

                <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                  <Shield className="w-3.5 h-3.5 text-emerald-400" />
                  <span>POLICY v{selectedAgent.policy?.version || '1.0'}</span>
                </div>
              </div>

              {/* Authorized Objective */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
                  <Lock className="w-3.5 h-3.5 text-sky-400" />
                  <span>MANDATED TASK OBJECTIVE</span>
                </h3>
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/80 text-xs text-slate-200 leading-relaxed font-sans">
                  "{selectedAgent.authorized_objective}"
                </div>
              </div>

              {/* Security Manifest Specs */}
              {selectedAgent.policy && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Allowed Tools */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold flex items-center space-x-1.5">
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                      <span>PERMITTED TOOLS (WHITELIST)</span>
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedAgent.policy.allowed_tools.map((t, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 text-xs font-mono"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Allowed Operations */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold flex items-center space-x-1.5">
                      <Shield className="w-3.5 h-3.5 text-sky-400" />
                      <span>PERMITTED OPERATIONS</span>
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedAgent.policy.allowed_operations.map((op, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/20 text-xs font-mono"
                        >
                          {op}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Filesystem Allowed Paths */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold flex items-center space-x-1.5">
                      <FileText className="w-3.5 h-3.5 text-slate-300" />
                      <span>ALLOWED PATHS (SCOPE)</span>
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedAgent.policy.allowed_paths.map((p, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-xs font-mono"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Denied Paths */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold flex items-center space-x-1.5">
                      <XCircle className="w-3.5 h-3.5 text-rose-400" />
                      <span>RESTRICTED PATHS (HONEYTOKENS)</span>
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedAgent.policy.denied_paths.map((dp, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 text-xs font-mono"
                        >
                          {dp}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Allowed Network Domains */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold flex items-center space-x-1.5">
                      <Globe className="w-3.5 h-3.5 text-sky-400" />
                      <span>APPROVED NETWORK DESTINATIONS</span>
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedAgent.policy.allowed_network_domains.length > 0 ? (
                        selectedAgent.policy.allowed_network_domains.map((dom, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/20 text-xs font-mono"
                          >
                            {dom}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-slate-500 italic">No external network egress allowed</span>
                      )}
                    </div>
                  </div>

                  {/* Quarantine Threshold */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold flex items-center space-x-1.5">
                      <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                      <span>ANTI-BRUTE FORCE / QUARANTINE</span>
                    </span>
                    <div className="text-xs text-slate-300 font-mono">
                      Locks session after{' '}
                      <span className="text-amber-400 font-bold">
                        {selectedAgent.policy.max_denial_threshold}
                      </span>{' '}
                      policy violations
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center text-slate-400 font-mono text-xs border border-slate-800 rounded-xl">
              Select an agent to inspect security configuration.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
