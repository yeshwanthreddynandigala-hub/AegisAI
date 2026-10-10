import React from 'react';
import { Shield, ShieldAlert, Cpu, CheckCircle2, RefreshCw } from 'lucide-react';

interface NavbarProps {
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ onRefresh, isRefreshing }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0d121f] px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-lg text-sky-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold tracking-wider text-slate-100 text-sm font-mono">AI BEHAVIOR SENTINEL</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
              RESEARCH PROTOTYPE v1.0
            </span>
          </div>
          <p className="text-xs text-slate-400">Autonomous Agent Threat Investigation & Zero-Trust Gateway</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Gateway Status Badge */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-700 text-xs text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="font-mono text-[11px] font-medium">GATEWAY: ACTIVE MEDIATION</span>
        </div>

        {/* Threat Isolation Badge */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-sky-950/40 border border-sky-800/40 text-xs text-sky-300 font-mono text-[11px]">
          <Cpu className="w-3.5 h-3.5 text-sky-400" />
          <span>SANDBOX: CONFINED</span>
        </div>

        {/* Refresh Action Button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors flex items-center space-x-1.5 text-xs font-mono"
            title="Refresh SecOps Telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
            <span className="hidden sm:inline">SYNC</span>
          </button>
        )}
      </div>
    </header>
  );
};
