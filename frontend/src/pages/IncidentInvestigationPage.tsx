import React, { useEffect, useState } from 'react';
import {
  AlertOctagon,
  Clock,
  Shield,
  FileCheck,
  CheckCircle2,
  XCircle,
  FileText,
  Sparkles,
  ArrowLeft,
  Activity
} from 'lucide-react';
import { api } from '../services/api';
import { Incident, IncidentDetail } from '../types';

interface IncidentInvestigationPageProps {
  initialIncidentId?: string | null;
  onClearIncidentSelection?: () => void;
}

export const IncidentInvestigationPage: React.FC<IncidentInvestigationPageProps> = ({
  initialIncidentId,
  onClearIncidentSelection
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(initialIncidentId || null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [investigating, setInvestigating] = useState<boolean>(false);
  const [investigationReport, setInvestigationReport] = useState<string | null>(null);

  useEffect(() => {
    loadIncidents();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const loadIncidents = async () => {
    try {
      const data = await api.getIncidents();
      setIncidents(data);
      if (data.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(data[0].incident_id);
      }
    } catch (err) {
      console.error('Failed to load incidents:', err);
    }
  };

  const loadIncidentDetail = async (id: string) => {
    try {
      setLoading(true);
      const data = await api.getIncidentDetail(id);
      setDetail(data);
      setInvestigationReport(data.investigation_report || null);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerInvestigation = async () => {
    if (!selectedIncidentId) return;
    try {
      setInvestigating(true);
      const res = await api.investigateIncident(selectedIncidentId, 'offline');
      setInvestigationReport(res.report);
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setInvestigating(false);
    }
  };

  const handleContainIncident = async () => {
    if (!selectedIncidentId) return;
    try {
      await api.containIncident(selectedIncidentId);
      if (detail) {
        setDetail({ ...detail, status: 'CONTAINED' });
      }
      loadIncidents();
    } catch (err) {
      console.error('Failed to contain incident:', err);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
            <AlertOctagon className="w-5 h-5 text-rose-400" />
            <span>INCIDENT INVESTIGATION & ATTACK TIMELINES</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Reconstruct multi-step causal attack sequences with verified event evidence citations.
          </p>
        </div>

        {initialIncidentId && onClearIncidentSelection && (
          <button
            onClick={onClearIncidentSelection}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono flex items-center space-x-1.5"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>ALL INCIDENTS</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incident List */}
        <div className="space-y-3 lg:col-span-1">
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
            DETECTED INCIDENTS ({incidents.length})
          </h2>

          <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
            {incidents.map((inc) => {
              const isSelected = selectedIncidentId === inc.incident_id;
              return (
                <div
                  key={inc.incident_id}
                  onClick={() => setSelectedIncidentId(inc.incident_id)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-rose-500/10 border-rose-500/40 text-white shadow-lg shadow-rose-950/20'
                      : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
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
                    <span className="font-mono text-[10px] text-slate-400">
                      {new Date(inc.created_at).toLocaleTimeString()}
                    </span>
                  </div>

                  <h3 className="font-semibold text-xs text-slate-100 line-clamp-1">{inc.title}</h3>
                  <div className="flex items-center justify-between mt-2 text-[11px] font-mono text-slate-400">
                    <span className="text-sky-400 truncate max-w-[130px]">{inc.agent_id}</span>
                    <span>{inc.status}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Deep Incident Timeline & Dossier */}
        <div className="lg:col-span-2 space-y-6">
          {detail ? (
            <div className="space-y-6">
              {/* Incident Header Dossier Card */}
              <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs text-rose-400 font-bold uppercase">
                        {detail.primary_threat_category}
                      </span>
                      <span className="text-slate-600">•</span>
                      <span className="font-mono text-xs text-slate-400">ID: {detail.incident_id.slice(0, 12)}</span>
                    </div>
                    <h2 className="text-base font-bold text-white mt-1">{detail.title}</h2>
                  </div>

                  <div className="flex items-center space-x-2">
                    {detail.status !== 'CONTAINED' && (
                      <button
                        onClick={handleContainIncident}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 text-xs font-mono font-medium"
                      >
                        CONTAIN INCIDENT
                      </button>
                    )}
                    <button
                      onClick={handleTriggerInvestigation}
                      disabled={investigating}
                      className="px-3 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-600 text-white text-xs font-mono font-medium flex items-center space-x-1.5 shadow"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>{investigating ? 'ANALYZING...' : 'INVESTIGATE DOSSIER'}</span>
                    </button>
                  </div>
                </div>

                <div className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-950 p-3 rounded-lg border border-slate-800">
                  {detail.summary}
                </div>

                {/* Evidence Stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px]">CONFIDENCE</span>
                    <div className="text-emerald-400 font-bold">{(detail.confidence_score * 100).toFixed(0)}%</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px]">MITIGATION</span>
                    <div className="text-slate-300 font-bold truncate">{detail.mitigation_status}</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px]">ENGINES FIRED</span>
                    <div className="text-sky-400 font-bold truncate">
                      {detail.detection_engines?.join(', ') || 'rule_engine'}
                    </div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px]">EVIDENCE EVENTS</span>
                    <div className="text-rose-400 font-bold">{detail.evidence_event_ids?.length || 1} Events</div>
                  </div>
                </div>
              </div>

              {/* Chronological Attack Timeline */}
              <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                    <Clock className="w-4 h-4 text-sky-400" />
                    <span>CHRONOLOGICAL CAUSAL ATTACK TIMELINE</span>
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400">
                    {detail.timeline_events.length} Events in Session
                  </span>
                </div>

                <div className="relative border-l border-slate-800 ml-4 space-y-6 pl-6 py-2">
                  {detail.timeline_events.map((evt, idx) => {
                    const isEvidence = detail.evidence_event_ids?.includes(evt.event_id);
                    const isBlocked = evt.execution_status === 'BLOCKED';

                    return (
                      <div key={evt.event_id} className="relative group">
                        {/* Timeline Node Icon */}
                        <div
                          className={`absolute -left-[31px] top-1 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-mono font-bold border ${
                            isEvidence
                              ? 'bg-rose-500 text-white border-rose-400 ring-4 ring-rose-500/20'
                              : isBlocked
                              ? 'bg-amber-500 text-white border-amber-400'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          }`}
                        >
                          {idx + 1}
                        </div>

                        {/* Event Content Box */}
                        <div
                          className={`p-4 rounded-xl border transition-all ${
                            isEvidence
                              ? 'bg-rose-500/10 border-rose-500/40 text-slate-200'
                              : 'bg-slate-950 border-slate-800/80 text-slate-300'
                          }`}
                        >
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-2">
                            <div className="flex items-center space-x-2">
                              <span className="font-mono text-xs font-bold text-sky-400">
                                {evt.tool_name || evt.action_type}
                              </span>
                              {isEvidence && (
                                <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] font-mono border border-rose-500/30">
                                  PRIMARY EVIDENCE
                                </span>
                              )}
                            </div>
                            <span className="font-mono text-[10px] text-slate-400">
                              {new Date(evt.timestamp).toLocaleTimeString()} UTC
                            </span>
                          </div>

                          <div className="text-xs font-mono text-slate-300 mb-2">
                            <span className="text-slate-500">Target: </span>
                            <span className="text-slate-200">{evt.resource || 'None'}</span>
                          </div>

                          <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800/60 font-mono">
                            <div className="flex items-center space-x-2">
                              <span className="text-slate-500 text-[10px]">DECISION:</span>
                              <span
                                className={`font-bold ${
                                  evt.policy_decision === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'
                                }`}
                              >
                                {evt.policy_decision}
                              </span>
                            </div>

                            <div className="flex items-center space-x-1 text-slate-400 text-[11px]">
                              {evt.execution_status === 'EXECUTED' ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <XCircle className="w-3.5 h-3.5 text-rose-400" />
                              )}
                              <span>{evt.execution_status}</span>
                            </div>
                          </div>

                          {evt.execution_output && (
                            <div className="mt-2 text-[10px] font-mono text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800">
                              {evt.execution_output}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Generated Investigation Report Markdown Viewer */}
              {investigationReport && (
                <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                      <FileCheck className="w-4 h-4 text-emerald-400" />
                      <span>EVIDENCE-GROUNDED INVESTIGATION DOSSIER</span>
                    </h3>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      HALLUCINATION-RESISTANT
                    </span>
                  </div>

                  <div className="p-5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 leading-relaxed font-mono whitespace-pre-wrap max-h-96 overflow-y-auto">
                    {investigationReport}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center text-slate-400 font-mono text-xs border border-slate-800 rounded-xl">
              {loading ? 'Reconstructing incident timeline...' : 'Select an incident to view investigation details.'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
