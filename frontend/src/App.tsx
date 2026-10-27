import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LoginPage } from './pages/LoginPage';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { LiveMonitorPage } from './pages/LiveMonitorPage';
import { AgentExplorerPage } from './pages/AgentExplorerPage';
import { IncidentInvestigationPage } from './pages/IncidentInvestigationPage';
import { SimulationLabPage } from './pages/SimulationLabPage';
import { EvaluationCenterPage } from './pages/EvaluationCenterPage';
import { ThreatCorrelationPage } from './pages/ThreatCorrelationPage';
import { ApprovalsInboxPage } from './pages/ApprovalsInboxPage';
import { api } from './services/api';
import { Shield } from 'lucide-react';

const MainDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [focusedIncidentId, setFocusedIncidentId] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState<number>(0);
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState<number>(0);
  const [openIncidentsCount, setOpenIncidentsCount] = useState<number>(0);

  const fetchBadgeCounts = async () => {
    try {
      const stats = await api.getOverviewStats();
      if (stats.pending_approvals_count !== undefined) {
        setPendingApprovalsCount(stats.pending_approvals_count);
      }
      if (stats.high_critical_alerts_count !== undefined) {
        setOpenIncidentsCount(stats.high_critical_alerts_count);
      }
    } catch {
      // Ignore background badge fetch errors
    }
  };

  React.useEffect(() => {
    fetchBadgeCounts();
  }, [refreshKey, activeTab]);

  const handleNavigateToIncident = (incidentId: string) => {
    setFocusedIncidentId(incidentId);
    setActiveTab('incidents');
  };

  const handleNavigateToLiveMonitor = () => {
    setActiveTab('live_events');
  };

  const handleRefresh = () => {
    setRefreshKey((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans">
      <Navbar onRefresh={handleRefresh} />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          openIncidentsCount={openIncidentsCount}
          pendingApprovalsCount={pendingApprovalsCount}
          onTabChange={(tab) => {
            setActiveTab(tab);
            if (tab !== 'incidents') {
              setFocusedIncidentId(null);
            }
          }}
        />

        <main className="flex-1 overflow-y-auto bg-[#0a0d14]" key={refreshKey}>
          {activeTab === 'overview' && (
            <OverviewPage
              onNavigateToIncident={handleNavigateToIncident}
              onNavigateToLiveMonitor={handleNavigateToLiveMonitor}
            />
          )}

          {activeTab === 'live_events' && <LiveMonitorPage />}

          {activeTab === 'agents' && <AgentExplorerPage />}

          {activeTab === 'incidents' && (
            <IncidentInvestigationPage
              initialIncidentId={focusedIncidentId}
              onClearIncidentSelection={() => setFocusedIncidentId(null)}
            />
          )}

          {activeTab === 'approvals' && <ApprovalsInboxPage />}

          {activeTab === 'simulations' && (
            <SimulationLabPage onNavigateToIncident={handleNavigateToIncident} />
          )}

          {activeTab === 'evaluation' && <EvaluationCenterPage />}

          {activeTab === 'threat_intel' && (
            <ThreatCorrelationPage onNavigateToIncident={handleNavigateToIncident} />
          )}
        </main>
      </div>
    </div>
  );
};

const AuthenticatedApp: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#07090e] flex flex-col items-center justify-center text-slate-400 font-mono text-xs">
        <div className="w-12 h-12 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 mb-4 animate-pulse">
          <Shield className="w-6 h-6" />
        </div>
        <p className="tracking-widest uppercase text-slate-300">AUTHENTICATING SECURE SESSION...</p>
        <span className="text-[10px] text-slate-500 mt-1">Verifying cryptographic JWT signature & zero-trust identity</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return <MainDashboard />;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AuthenticatedApp />
    </AuthProvider>
  );
};

export default App;
