import React from 'react';
import {
  LayoutDashboard,
  Terminal,
  Bot,
  AlertOctagon,
  ClipboardCheck,
  FlaskConical,
  BarChart3,
  Share2,
  Lock,
  LogOut,
  UserCheck,
  ShieldCheck
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export type NavTab =
  | 'overview'
  | 'live_events'
  | 'agents'
  | 'incidents'
  | 'approvals'
  | 'simulations'
  | 'evaluation'
  | 'threat_intel';

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  openIncidentsCount?: number;
  pendingApprovalsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  openIncidentsCount = 0,
  pendingApprovalsCount = 0
}) => {
  const { user, logout, isAdmin } = useAuth();
  const navItems = [
    {
      id: 'overview' as NavTab,
      label: 'SOC Overview',
      icon: LayoutDashboard,
      description: 'System posture & key metrics'
    },
    {
      id: 'live_events' as NavTab,
      label: 'Live Telemetry',
      icon: Terminal,
      description: 'Intercepted tool events'
    },
    {
      id: 'agents' as NavTab,
      label: 'Agent Explorer',
      icon: Bot,
      description: 'Manifests & authorization scopes'
    },
    {
      id: 'incidents' as NavTab,
      label: 'Incident Dossier',
      icon: AlertOctagon,
      badge: openIncidentsCount > 0 ? openIncidentsCount : undefined,
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
      description: 'Attack timelines & citations'
    },
    {
      id: 'approvals' as NavTab,
      label: 'Approvals Inbox',
      icon: ClipboardCheck,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30 animate-pulse',
      description: 'Human-in-the-loop (HITL) gate'
    },
    {
      id: 'simulations' as NavTab,
      label: 'Simulation Lab',
      icon: FlaskConical,
      description: 'Controlled prompt injection suites'
    },
    {
      id: 'evaluation' as NavTab,
      label: 'Evaluation Center',
      icon: BarChart3,
      description: 'Rule vs Seq vs ML benchmarks'
    },
    {
      id: 'threat_intel' as NavTab,
      label: 'Threat Correlation',
      icon: Share2,
      description: 'Cross-incident behavioral graph'
    }
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#0d121f] flex flex-col justify-between shrink-0 h-[calc(100vh-4rem)]">
      <div className="p-3 space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono font-semibold tracking-wider text-slate-400 uppercase">
          OPERATIONAL MODULES
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-left transition-all ${
                isActive
                  ? 'bg-sky-500/10 border border-sky-500/30 text-sky-300 font-medium'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <div className="flex items-center space-x-3 truncate">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <div className="truncate">
                  <div className="text-xs font-medium truncate">{item.label}</div>
                  <div className="text-[10px] text-slate-400 truncate">{item.description}</div>
                </div>
              </div>

              {item.badge !== undefined && (
                <span
                  className={`ml-2 px-1.5 py-0.5 rounded text-[10px] font-mono border font-semibold ${
                    item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* User Session & Role Card */}
      <div className="border-t border-slate-800/80 bg-slate-950/60 p-3 space-y-3">
        {user && (
          <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/80 border border-slate-800">
            <div className="flex items-center space-x-2.5 truncate">
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 border ${
                  isAdmin
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                    : 'bg-sky-500/10 border-sky-500/30 text-sky-400'
                }`}
              >
                {isAdmin ? <ShieldCheck className="w-4 h-4" /> : <UserCheck className="w-4 h-4" />}
              </div>
              <div className="truncate">
                <div className="text-xs font-medium text-slate-200 truncate">
                  {user.full_name || user.username}
                </div>
                <div className="flex items-center space-x-1.5 mt-0.5">
                  <span
                    className={`text-[9px] font-mono px-1 py-0.2 rounded border font-semibold ${
                      isAdmin
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                        : 'bg-sky-500/20 text-sky-300 border-sky-500/30'
                    }`}
                  >
                    {user.role}
                  </span>
                  <span className="text-[10px] text-slate-500 truncate">@{user.username}</span>
                </div>
              </div>
            </div>

            <button
              onClick={logout}
              title="Sign Out"
              className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition-colors shrink-0"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Policy Note */}
        <div className="text-[10px] text-slate-500">
          <div className="flex items-center space-x-1 text-slate-400 font-mono mb-1">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>ZERO-TRUST ENFORCED</span>
          </div>
          <p className="leading-tight text-[10px]">
            {isAdmin
              ? 'Administrator privilege active. Policy configuration & containment authorized.'
              : 'Analyst privilege active. Investigation & telemetry authorized.'}
          </p>
        </div>
      </div>
    </aside>
  );
};
