import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { LiveMonitorPage } from './pages/LiveMonitorPage';
import { AgentExplorerPage } from './pages/AgentExplorerPage';
import { IncidentInvestigationPage } from './pages/IncidentInvestigationPage';
import { SimulationLabPage } from './pages/SimulationLabPage';
import { EvaluationCenterPage } from './pages/EvaluationCenterPage';
import { ThreatCorrelationPage } from './pages/ThreatCorrelationPage';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [focusedIncidentId, setFocusedIncidentId] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState<number>(0);

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

export default App;
