import React, { useEffect, useState } from 'react';
import {
  ClipboardCheck,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
  Shield,
  FileCode,
  Terminal,
  User,
  ArrowRight,
  Filter,
  Search,
  Check,
  X,
  Lock
} from 'lucide-react';
import { api } from '../services/api';
import { ApprovalRequest, ApprovalStatus } from '../types';
import { formatLocalDateTime, formatUtcDateTime } from '../utils/dateUtils';
import { useAuth } from '../context/AuthContext';

export const ApprovalsInboxPage: React.FC = () => {
  const { user } = useAuth();
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [justification, setJustification] = useState<string>('');
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    loadApprovals();
  }, [statusFilter]);

  const loadApprovals = async () => {
    setLoading(true);
    setActionError(null);
    try {
      const params: { status?: string } = {};
      if (statusFilter !== 'ALL') {
        params.status = statusFilter;
      }
      const data = await api.getApprovals(params);
      setApprovals(data);
      if (data.length > 0 && (!selectedId || !data.some((a) => a.approval_id === selectedId))) {
        setSelectedId(data[0].approval_id);
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to load approvals inbox.');
    } finally {
      setLoading(false);
    }
  };

  const selectedApproval = approvals.find((a) => a.approval_id === selectedId);

  const handleApprove = async () => {
    if (!selectedId) return;
    if (!justification.trim()) {
      setActionError('Please provide a review justification before approving.');
      return;
    }

    setSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await api.approveRequest(selectedId, justification.trim());
      setActionSuccess(`Approval ${updated.approval_id} approved successfully. Execution status: ${updated.status}`);
      setJustification('');
      await loadApprovals();
    } catch (err: any) {
      setActionError(err.message || 'Failed to approve request.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleReject = async () => {
    if (!selectedId) return;
    if (!justification.trim()) {
      setActionError('Please provide a review justification before rejecting.');
      return;
    }

    setSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await api.rejectRequest(selectedId, justification.trim());
      setActionSuccess(`Approval ${updated.approval_id} rejected. Action will never execute.`);
      setJustification('');
      await loadApprovals();
    } catch (err: any) {
      setActionError(err.message || 'Failed to reject request.');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredApprovals = approvals.filter((a) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.approval_id.toLowerCase().includes(q) ||
      a.tool_name.toLowerCase().includes(q) ||
      a.agent_id.toLowerCase().includes(q) ||
      (a.resource && a.resource.toLowerCase().includes(q))
    );
  });

  const getStatusBadge = (status: ApprovalStatus) => {
    switch (status) {
      case 'PENDING':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Clock className="w-3 h-3 animate-pulse" />
            <span>PENDING REVIEW</span>
          </span>
        );
      case 'IN_PROGRESS':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <RefreshCw className="w-3 h-3 animate-spin" />
            <span>PROCESSING</span>
          </span>
        );
      case 'EXECUTED':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            <span>APPROVED & EXECUTED</span>
          </span>
        );
      case 'APPROVED':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/30">
            <CheckCircle2 className="w-3 h-3" />
            <span>APPROVED</span>
          </span>
        );
      case 'REJECTED':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3" />
            <span>REJECTED</span>
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <AlertTriangle className="w-3 h-3" />
            <span>EXPIRED</span>
          </span>
        );
      case 'FAILED':
        return (
          <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
            <AlertTriangle className="w-3 h-3" />
            <span>EXECUTION FAILED</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-slate-800 text-slate-400">
            {status}
          </span>
        );
    }
  };

  const pendingCount = approvals.filter((a) => a.status === 'PENDING').length;

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2.5">
            <ClipboardCheck className="w-5 h-5 text-amber-400" />
            <span>HUMAN-IN-THE-LOOP (HITL) APPROVALS INBOX</span>
            {pendingCount > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-mono font-bold animate-pulse">
                {pendingCount} PENDING
              </span>
            )}
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Authorize or reject deferred agent tool actions requiring human confirmation. Approved actions undergo full zero-trust policy revalidation before sandbox execution.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={loadApprovals}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center space-x-1.5 transition-colors border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            <span>SYNC INBOX</span>
          </button>
        </div>
      </div>

      {/* Global Alerts */}
      {actionSuccess && (
        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>{actionSuccess}</span>
        </div>
      )}
      {actionError && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center space-x-2">
          <XCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Filter Tabs and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#0d121f] p-3 rounded-xl border border-slate-800">
        <div className="flex items-center space-x-1 overflow-x-auto w-full sm:w-auto">
          {['ALL', 'PENDING', 'IN_PROGRESS', 'EXECUTED', 'REJECTED', 'EXPIRED', 'FAILED'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all shrink-0 ${
                statusFilter === st
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search request ID, tool, resource..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
          />
        </div>
      </div>

      {/* Main Master-Detail Split Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: List of Requests */}
        <div className="lg:col-span-5 space-y-2.5 max-h-[calc(100vh-18rem)] overflow-y-auto pr-1">
          {loading && approvals.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 font-mono">
              <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
              Loading security approval queue...
            </div>
          ) : filteredApprovals.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 font-mono border border-slate-800/80 rounded-xl bg-[#0d121f]">
              <ClipboardCheck className="w-6 h-6 mx-auto mb-2 text-slate-600" />
              No approval requests match the selected filter.
            </div>
          ) : (
            filteredApprovals.map((item) => {
              const isSelected = item.approval_id === selectedId;
              return (
                <div
                  key={item.approval_id}
                  onClick={() => {
                    setSelectedId(item.approval_id);
                    setActionError(null);
                    setActionSuccess(null);
                  }}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-sky-950/20 border-sky-500/50 shadow-lg shadow-sky-500/5'
                      : 'bg-[#0d121f] border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs font-semibold text-slate-200">
                      {item.tool_name}
                    </span>
                    {getStatusBadge(item.status)}
                  </div>

                  <div className="text-[11px] font-mono text-slate-400 truncate mb-1">
                    Resource: <span className="text-slate-300">{item.resource || 'N/A'}</span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mt-2 pt-2 border-t border-slate-800/60">
                    <span>Agent: {item.agent_id}</span>
                    <span>{formatLocalDateTime(item.created_at)}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Detailed Review & Decision Inspector */}
        <div className="lg:col-span-7">
          {selectedApproval ? (
            <div className="bg-[#0d121f] border border-slate-800 rounded-2xl p-6 space-y-6">
              {/* Header Details */}
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-semibold text-slate-400">REQUEST ID:</span>
                    <span className="text-xs font-mono font-bold text-sky-400">{selectedApproval.approval_id}</span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-sky-400" />
                    <span>Tool Invocation: {selectedApproval.tool_name}</span>
                  </h2>
                </div>
                <div>{getStatusBadge(selectedApproval.status)}</div>
              </div>

              {/* Security Policy Reason & Risk Tags */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <div className="flex items-center space-x-2 text-[11px] font-mono text-amber-400">
                  <Shield className="w-3.5 h-3.5" />
                  <span>POLICY DECISION CONTEXT</span>
                </div>
                <p className="text-xs text-slate-300 font-sans leading-relaxed">
                  {selectedApproval.decision_reason || 'This sensitive operation requires explicit human confirmation before execution.'}
                </p>
                {selectedApproval.risk_indicators && selectedApproval.risk_indicators.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {selectedApproval.risk_indicators.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-mono text-[10px]"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Session and Metadata Grid */}
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 block">REQUESTING AGENT</span>
                  <span className="text-slate-200 font-medium">{selectedApproval.agent_id}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 block">SESSION ID</span>
                  <span className="text-slate-200 font-medium truncate block">{selectedApproval.session_id}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 block">REQUESTED AT</span>
                  <span className="text-slate-200">
                    {formatLocalDateTime(selectedApproval.created_at)} ({formatUtcDateTime(selectedApproval.created_at)})
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 block">EXPIRATION WINDOW</span>
                  <span className="text-slate-200">
                    {formatLocalDateTime(selectedApproval.expires_at)} ({formatUtcDateTime(selectedApproval.expires_at)})
                  </span>
                </div>
              </div>

              {/* Tool Parameters JSON Inspector */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                  <span className="flex items-center space-x-1.5">
                    <FileCode className="w-3.5 h-3.5 text-sky-400" />
                    <span>VALIDATED PARAMETERS</span>
                  </span>
                  <span className="text-[10px] text-slate-500">Target: {selectedApproval.resource || 'sandbox'}</span>
                </div>
                <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-sky-300 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedApproval.parameters, null, 2)}
                </pre>
              </div>

              {/* Action Decision Box (If PENDING) */}
              {selectedApproval.status === 'PENDING' ? (
                <div className="p-4 rounded-xl bg-slate-900/80 border border-amber-500/30 space-y-3.5">
                  <div className="flex items-center space-x-2 text-xs font-mono text-amber-300 font-semibold">
                    <User className="w-4 h-4 text-amber-400" />
                    <span>AUTHORIZATION REVIEW DECISION</span>
                  </div>

                  {/* Justification Field */}
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1.5">
                      REVIEWER JUSTIFICATION (REQUIRED FOR AUDIT LOG):
                    </label>
                    <textarea
                      rows={2}
                      value={justification}
                      onChange={(e) => setJustification(e.target.value)}
                      placeholder="e.g. Verified target file is within scheduled operational task scope."
                      className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors font-mono resize-none"
                    />
                  </div>

                  {/* Quick-fill Reason Templates */}
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      'Verified legitimate scheduled maintenance write.',
                      'Target file and path conform to operational objective.',
                      'Suspicious write rejected due to unapproved target directory.',
                      'Exfiltration risk: write rejected by security analyst.'
                    ].map((tmpl, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => setJustification(tmpl)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-[10px] font-mono transition-colors"
                      >
                        + {tmpl}
                      </button>
                    ))}
                  </div>

                  {/* Decision Buttons */}
                  <div className="flex items-center justify-end space-x-3 pt-2 border-t border-slate-800/80">
                    <button
                      onClick={handleReject}
                      disabled={submitting}
                      className="px-4 py-2 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-mono font-medium flex items-center space-x-1.5 transition-all disabled:opacity-50"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>{submitting ? 'PROCESSING...' : 'REJECT ACTION'}</span>
                    </button>

                    <button
                      onClick={handleApprove}
                      disabled={submitting}
                      className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-xs font-mono font-medium flex items-center space-x-1.5 transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>{submitting ? 'REVALIDATING & EXECUTING...' : 'APPROVE & EXECUTE'}</span>
                    </button>
                  </div>

                  <div className="flex items-center space-x-1.5 text-[10px] font-mono text-slate-500 pt-1">
                    <Lock className="w-3 h-3 text-emerald-400 shrink-0" />
                    <span>Zero-Trust Policy: Approving triggers full policy revalidation before sandbox execution.</span>
                  </div>
                </div>
              ) : (
                /* Audit Trail & Execution Outcome (If already decided) */
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                  <div className="flex items-center space-x-2 text-xs font-mono text-slate-300 font-semibold">
                    <ClipboardCheck className="w-4 h-4 text-sky-400" />
                    <span>REVIEW AUDIT TRAIL</span>
                  </div>

                  {selectedApproval.status === 'IN_PROGRESS' && (
                    <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center space-x-2">
                      <RefreshCw className="w-4 h-4 shrink-0 animate-spin text-cyan-400" />
                      <span>Request is actively executing in sandbox environment.</span>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                    <div>
                      <span className="text-[10px] text-slate-500 block">REVIEWED BY</span>
                      <span className="text-slate-200">@{selectedApproval.reviewed_by_username || 'system'}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">REVIEW TIMESTAMP</span>
                      <span className="text-slate-200">
                        {selectedApproval.reviewed_at ? formatLocalDateTime(selectedApproval.reviewed_at) : 'N/A'}
                      </span>
                    </div>
                  </div>

                  {selectedApproval.review_justification && (
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 text-xs text-slate-300 font-mono">
                      <span className="text-[10px] text-slate-500 block mb-0.5">JUSTIFICATION</span>
                      "{selectedApproval.review_justification}"
                    </div>
                  )}

                  {selectedApproval.execution_output && (
                    <div>
                      <span className="text-[10px] text-slate-500 font-mono block mb-1">EXECUTION OUTCOME</span>
                      <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-32">
                        {selectedApproval.execution_output}
                      </pre>
                    </div>
                  )}

                  {selectedApproval.failure_reason && (
                    <div>
                      <span className="text-[10px] text-rose-400 font-mono block mb-1">REASON / OUTCOME NOTE</span>
                      <p className="text-xs text-rose-300 font-mono bg-rose-500/10 p-2.5 rounded-lg border border-rose-500/20">
                        {selectedApproval.failure_reason}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-slate-500 font-mono border border-slate-800 rounded-2xl bg-[#0d121f]">
              Select an approval request from the left column to inspect its parameters and make an authorization decision.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
