import React, { useEffect, useState } from 'react';
import {
  FlaskConical,
  Play,
  ShieldCheck,
  ShieldAlert,
  Clock,
  ArrowRight,
  CheckCircle2,
  XCircle,
  FileCode,
  Terminal,
  Activity
} from 'lucide-react';
import { api } from '../services/api';
import { SimulationScenario, SimulationRunResult } from '../types';

interface SimulationLabPageProps {
  onNavigateToIncident?: (incidentId: string) => void;
}

export const SimulationLabPage: React.FC<SimulationLabPageProps> = ({ onNavigateToIncident }) => {
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<SimulationScenario | null>(null);
  const [running, setRunning] = useState<boolean>(false);
  const [runResult, setRunResult] = useState<SimulationRunResult | null>(null);

  useEffect(() => {
    loadScenarios();
  }, []);

  const loadScenarios = async () => {
    try {
      const data = await api.getScenarios();
      setScenarios(data);
      if (data.length > 0) setSelectedScenario(data[0]);
    } catch (err) {
      console.error('Failed to load scenarios:', err);
    }
  };

  const handleRunSimulation = async () => {
    if (!selectedScenario) return;
    try {
      setRunning(true);
      setRunResult(null);
      const res = await api.runSimulation(selectedScenario.scenario_id);
      setRunResult(res);
    } catch (err) {
      console.error('Simulation execution failed:', err);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
          <FlaskConical className="w-5 h-5 text-sky-400" />
          <span>ATTACK SIMULATION & EVALUATION LAB</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Safely launch controlled benign tasks, indirect prompt injections, credential probes, and unseen zero-day trajectories against the Gateway.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scenario Selector */}
        <div className="space-y-3 lg:col-span-1">
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
            SCENARIO CATALOG ({scenarios.length})
          </h2>

          <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
            {scenarios.map((sc) => {
              const isSelected = selectedScenario?.scenario_id === sc.scenario_id;
              return (
                <div
                  key={sc.scenario_id}
                  onClick={() => setSelectedScenario(sc)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-sky-500/10 border-sky-500/40 text-white shadow-lg shadow-sky-950/20'
                      : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        sc.is_unseen
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                          : sc.is_attack
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {sc.is_unseen ? 'UNSEEN ZERO-DAY' : sc.is_attack ? 'ATTACK SCENARIO' : 'BENIGN TASK'}
                    </span>
                    <span className="font-mono text-[10px] text-slate-400">{sc.step_count} Steps</span>
                  </div>

                  <h3 className="font-semibold text-xs text-slate-100">{sc.name}</h3>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{sc.description}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Execution Console & Live Telemetry Output */}
        <div className="lg:col-span-2 space-y-6">
          {selectedScenario && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
              {/* Scenario Summary */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs text-sky-400">{selectedScenario.scenario_id}</span>
                    <span className="text-slate-600">•</span>
                    <span className="font-mono text-xs text-slate-400">Agent: {selectedScenario.agent_id}</span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1">{selectedScenario.name}</h2>
                </div>

                <button
                  onClick={handleRunSimulation}
                  disabled={running}
                  className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-600 text-white text-xs font-mono font-medium flex items-center space-x-2 shadow-lg shadow-sky-500/20 disabled:opacity-50"
                >
                  <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
                  <span>{running ? 'EXECUTING THROUGH GATEWAY...' : 'RUN SIMULATION'}</span>
                </button>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
                {selectedScenario.description}
              </div>

              {/* Execution Results View */}
              {runResult && (
                <div className="space-y-4 pt-2">
                  {/* Verdict Banner */}
                  <div
                    className={`p-4 rounded-xl border flex items-center justify-between ${
                      runResult.gateway_protected_safely
                        ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                        : 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      {runResult.gateway_protected_safely ? (
                        <ShieldCheck className="w-6 h-6 text-emerald-400" />
                      ) : (
                        <ShieldAlert className="w-6 h-6 text-rose-400" />
                      )}
                      <div>
                        <div className="font-bold text-sm font-mono">
                          {runResult.is_attack
                            ? 'ATTACK INTERCEPTED & MITIGATED AT GATEWAY'
                            : 'BENIGN WORKFLOW EXECUTED SAFELY'}
                        </div>
                        <div className="text-xs opacity-90 font-sans mt-0.5">
                          {runResult.is_attack
                            ? `Gateway blocked ${runResult.blocked_steps} unauthorized operation(s). No host compromise occurred.`
                            : `All ${runResult.executed_steps} operations satisfied authorized scope.`}
                        </div>
                      </div>
                    </div>

                    <div className="text-right font-mono text-xs">
                      <div className="font-bold">{runResult.execution_time_ms} ms</div>
                      <div className="text-[10px] opacity-75">LATENCY</div>
                    </div>
                  </div>

                  {/* Step-by-Step Interception Trace */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                      GATEWAY STEP INTERCEPTION TRACE ({runResult.step_results.length} STEPS)
                    </h4>

                    <div className="space-y-2 font-mono text-xs">
                      {runResult.step_results.map((st) => (
                        <div
                          key={st.step_number}
                          className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5"
                        >
                          <div className="flex items-center justify-between text-[11px]">
                            <div className="flex items-center space-x-2">
                              <span className="w-5 h-5 rounded-full bg-slate-800 flex items-center justify-center font-bold text-[10px] text-slate-300">
                                {st.step_number}
                              </span>
                              <span className="font-bold text-sky-400">{st.tool}</span>
                            </div>

                            <div className="flex items-center space-x-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  st.policy_decision === 'ALLOW'
                                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                    : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                }`}
                              >
                                {st.policy_decision}
                              </span>
                              <span
                                className={`text-[11px] font-semibold ${
                                  st.execution_status === 'EXECUTED' ? 'text-emerald-400' : 'text-rose-400'
                                }`}
                              >
                                {st.execution_status}
                              </span>
                            </div>
                          </div>

                          <div className="text-[11px] text-slate-400 pl-7">
                            <span className="text-slate-600">Params: </span>
                            {JSON.stringify(st.params)}
                          </div>

                          <div className="text-[10px] text-slate-400 pl-7 italic">
                            Reason: {st.decision_reason}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Incident Link if generated */}
                  {runResult.incidents_created.length > 0 && onNavigateToIncident && (
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                      <div className="flex items-center space-x-2 text-rose-300 font-mono">
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
                        <span>Security Incident Dossier Created ({runResult.incidents_created.length})</span>
                      </div>
                      <button
                        onClick={() => onNavigateToIncident(runResult.incidents_created[0])}
                        className="text-sky-400 hover:text-sky-300 font-mono text-xs flex items-center space-x-1"
                      >
                        <span>Open Incident Dossier</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
