import React, { useEffect, useState } from 'react';
import {
  Share2,
  Shield,
  Network,
  AlertTriangle,
  Info,
  CheckCircle2,
  RefreshCw,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';
import { ThreatGraphData, ThreatGraphNode, ThreatGraphEdge } from '../types';

interface ThreatCorrelationPageProps {
  onNavigateToIncident?: (incidentId: string) => void;
}

export const ThreatCorrelationPage: React.FC<ThreatCorrelationPageProps> = ({ onNavigateToIncident }) => {
  const [graphData, setGraphData] = useState<ThreatGraphData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<ThreatGraphNode | null>(null);

  useEffect(() => {
    loadGraph();
  }, []);

  const loadGraph = async () => {
    try {
      setLoading(true);
      const data = await api.getThreatGraph();
      setGraphData(data);
    } catch (err) {
      console.error('Failed to load threat graph:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Title & Attribution Warning */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
            <Share2 className="w-5 h-5 text-sky-400" />
            <span>CROSS-INCIDENT THREAT CORRELATION & CAMPAIGN GRAPH</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Behavioral clustering of incidents sharing targeted resources, attack vectors, and multi-step action trajectories.
          </p>
        </div>

        <button
          onClick={loadGraph}
          disabled={loading}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 flex items-center space-x-2"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          <span>RECOMPUTE CLUSTERS</span>
        </button>
      </div>

      {/* Scientific Attribution Disclaimer Banner */}
      <div className="p-4 rounded-xl bg-sky-950/20 border border-sky-800/40 text-xs text-sky-200 flex items-start space-x-3">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-bold font-mono text-[11px] uppercase tracking-wider text-sky-300">
            RESEARCH ATTRIBUTION DISCLAIMER
          </p>
          <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
            Correlations represent mathematical similarity between observed behavioral sequences and synthetic honeytoken targets.
            The system strictly distinguishes between shared behavioral signatures and real-world human identity. No real-world personal attribution is inferred.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Node & Edge Network Visualization Card */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <Network className="w-4 h-4 text-sky-400" />
              <span>BEHAVIORAL INCIDENT CLUSTER MAP</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-400">
              {graphData?.total_nodes || 0} Nodes • {graphData?.total_edges || 0} Similarity Edges
            </span>
          </div>

          {/* Interactive Topology Graph Grid */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 min-h-[380px] flex flex-wrap gap-3 items-center justify-center relative overflow-hidden">
            {graphData?.nodes && graphData.nodes.length > 0 ? (
              graphData.nodes.map((node) => {
                const isCat = node.type === 'THREAT_CATEGORY';
                const isSelected = selectedNode?.id === node.id;

                return (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`p-3 rounded-xl border cursor-pointer transition-all flex flex-col items-center justify-center text-center max-w-[170px] ${
                      isCat
                        ? 'bg-slate-900 border-sky-500/40 text-sky-300 shadow-md'
                        : node.severity === 'CRITICAL'
                        ? 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                        : 'bg-slate-900 border-slate-800 text-slate-300'
                    } ${isSelected ? 'ring-2 ring-sky-400 scale-105' : 'hover:scale-102'}`}
                  >
                    <div className="text-[10px] font-mono font-bold uppercase text-slate-500 mb-1">
                      {isCat ? 'CATEGORY HUB' : node.severity || 'INCIDENT'}
                    </div>
                    <div className="font-mono text-xs font-semibold truncate w-full">{node.label}</div>
                    {node.agent_id && (
                      <div className="text-[10px] text-sky-400 mt-1 font-mono truncate">{node.agent_id}</div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="text-xs text-slate-500 font-mono">
                No incidents available. Run simulation scenarios to generate graph clusters.
              </div>
            )}
          </div>

          {/* Edge Similarity Relationships */}
          <div className="space-y-2 pt-2">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
              IDENTIFIED CORRELATION EDGES ({graphData?.edges?.length || 0})
            </h4>

            <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-xs pr-1">
              {graphData?.edges && graphData.edges.length > 0 ? (
                graphData.edges.map((e, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-center justify-between text-[11px]"
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <span className="text-sky-400 truncate max-w-[140px]">{e.source.slice(0, 14)}</span>
                      <span className="text-slate-600">--[{e.relationship}]--&gt;</span>
                      <span className="text-slate-300 truncate max-w-[140px]">{e.target.slice(0, 14)}</span>
                    </div>

                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/20 text-[10px]">
                        Weight: {(e.weight * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-[11px] text-slate-500 italic">No multi-incident edges detected yet.</div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Cluster Node Inspector */}
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4 lg:col-span-1 h-fit sticky top-20">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              GRAPH NODE INSPECTOR
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">Click any cluster node to inspect profile</p>
          </div>

          {selectedNode ? (
            <div className="space-y-3 font-mono text-xs">
              <div>
                <span className="text-slate-500 text-[10px]">NODE IDENTIFIER</span>
                <div className="text-slate-200 break-all bg-slate-950 p-1.5 rounded border border-slate-800 text-[11px]">
                  {selectedNode.id}
                </div>
              </div>

              <div>
                <span className="text-slate-500 text-[10px]">LABEL / TITLE</span>
                <div className="text-white font-semibold">{selectedNode.label}</div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500 text-[10px]">NODE TYPE</span>
                  <div className="text-sky-400">{selectedNode.type}</div>
                </div>
                {selectedNode.severity && (
                  <div>
                    <span className="text-slate-500 text-[10px]">SEVERITY</span>
                    <div className="text-rose-400 font-bold">{selectedNode.severity}</div>
                  </div>
                )}
              </div>

              {selectedNode.agent_id && (
                <div>
                  <span className="text-slate-500 text-[10px]">INVOLVED AGENT</span>
                  <div className="text-sky-400">{selectedNode.agent_id}</div>
                </div>
              )}

              {selectedNode.type === 'INCIDENT' && onNavigateToIncident && (
                <button
                  onClick={() => onNavigateToIncident(selectedNode.id)}
                  className="w-full mt-3 py-2 px-3 bg-sky-500 hover:bg-sky-600 rounded-lg text-white font-mono text-xs flex items-center justify-center space-x-1.5"
                >
                  <span>Open Full Incident Dossier</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              Select a cluster node in the map to view metadata.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
