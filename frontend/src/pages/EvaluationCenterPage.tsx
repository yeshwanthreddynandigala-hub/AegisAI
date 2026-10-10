import React, { useEffect, useState } from 'react';
import {
  BarChart3,
  Play,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Info,
  Clock,
  Zap,
  ShieldCheck,
  Activity
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { api } from '../services/api';
import { BenchmarkSummary } from '../types';

export const EvaluationCenterPage: React.FC = () => {
  const [benchmark, setBenchmark] = useState<BenchmarkSummary | null>(null);
  const [running, setRunning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadBenchmark();
  }, []);

  const loadBenchmark = async () => {
    try {
      const data = await api.getEvaluationResults();
      setBenchmark(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch benchmark data.');
    }
  };

  const handleRunBenchmark = async () => {
    try {
      setRunning(true);
      const data = await api.runBenchmark();
      setBenchmark(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Benchmark execution failed.');
    } finally {
      setRunning(false);
    }
  };

  const chartData = benchmark
    ? [
        {
          name: 'Precision',
          Rule: benchmark.comparison.rule.precision,
          Sequence: benchmark.comparison.sequence.precision,
          ML: benchmark.comparison.ml.precision,
          Combined: benchmark.comparison.combined.precision
        },
        {
          name: 'Recall',
          Rule: benchmark.comparison.rule.recall,
          Sequence: benchmark.comparison.sequence.recall,
          ML: benchmark.comparison.ml.recall,
          Combined: benchmark.comparison.combined.recall
        },
        {
          name: 'F1 Score',
          Rule: benchmark.comparison.rule.f1,
          Sequence: benchmark.comparison.sequence.f1,
          ML: benchmark.comparison.ml.f1,
          Combined: benchmark.comparison.combined.f1
        }
      ]
    : [];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title & Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center space-x-2">
            <BarChart3 className="w-5 h-5 text-sky-400" />
            <span>EMPIRICAL EVALUATION & RESEARCH BENCHMARKS</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Comparative performance evaluation: Rule-Based vs Behavioral Sequence vs ML Anomaly vs Combined Defense.
          </p>
        </div>

        <button
          onClick={handleRunBenchmark}
          disabled={running}
          className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-600 text-white text-xs font-mono font-medium flex items-center space-x-2 shadow-lg shadow-sky-500/20 disabled:opacity-50"
        >
          <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
          <span>{running ? 'EVALUATING TESTBED...' : 'RUN BENCHMARK SUITE'}</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {error}
        </div>
      )}

      {benchmark ? (
        <div className="space-y-8">
          {/* Summary Dataset Stat Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">TOTAL SCENARIOS</span>
              <div className="text-xl font-bold font-mono text-white mt-1">{benchmark.total_scenarios}</div>
              <div className="text-[10px] text-slate-400">Standardized test suite</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">BENIGN TASKS</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{benchmark.benign_count}</div>
              <div className="text-[10px] text-slate-400">Normal operations</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">KNOWN ATTACKS</span>
              <div className="text-xl font-bold font-mono text-rose-400 mt-1">{benchmark.attack_count}</div>
              <div className="text-[10px] text-slate-400">Injections & harvests</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">UNSEEN ZERO-DAYS</span>
              <div className="text-xl font-bold font-mono text-purple-400 mt-1">{benchmark.unseen_count}</div>
              <div className="text-[10px] text-slate-400">Out-of-distribution drift</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500">BLOCKING EFFICACY</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                {(benchmark.blocking_effectiveness * 100).toFixed(0)}%
              </div>
              <div className="text-[10px] text-slate-400">Gateway zero-trust</div>
            </div>
          </div>

          {/* Comparative Metrics Table */}
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                  EMPIRICAL DETECTION COMPARISON TABLE
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Direct evaluation of each detector across the exact same scenario runs.
                </p>
              </div>
              <span className="text-[10px] font-mono text-slate-400">MEASURED AT {benchmark.timestamp}</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="border-b border-slate-800 text-[10px] text-slate-400 uppercase">
                  <tr>
                    <th className="py-2.5 px-3">DETECTION APPROACH</th>
                    <th className="py-2.5 px-3 text-center">PRECISION</th>
                    <th className="py-2.5 px-3 text-center">RECALL</th>
                    <th className="py-2.5 px-3 text-center">F1 SCORE</th>
                    <th className="py-2.5 px-3 text-center">FALSE POSITIVE (FPR)</th>
                    <th className="py-2.5 px-3 text-center">FALSE NEGATIVE (FNR)</th>
                    <th className="py-2.5 px-3 text-center">UNSEEN ACCURACY</th>
                    <th className="py-2.5 px-3 text-right">AVG LATENCY</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {/* Baseline: Rule-Based */}
                  <tr className="hover:bg-slate-800/40">
                    <td className="py-3 px-3 font-semibold text-slate-100 flex items-center space-x-2">
                      <span className="w-2 h-2 rounded-full bg-slate-400"></span>
                      <span>Baseline A: Rule-Based Detector</span>
                    </td>
                    <td className="py-3 px-3 text-center">{benchmark.comparison.rule.precision.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center">{benchmark.comparison.rule.recall.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center font-bold text-sky-400">
                      {benchmark.comparison.rule.f1.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-400">
                      {benchmark.comparison.rule.fpr.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-rose-400">
                      {benchmark.comparison.rule.fnr.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-400">
                      {(benchmark.unseen_accuracy.rule * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-3 text-right">{benchmark.comparison.rule.avg_latency_ms} ms</td>
                  </tr>

                  {/* Baseline B: Sequence Detector */}
                  <tr className="hover:bg-slate-800/40">
                    <td className="py-3 px-3 font-semibold text-slate-100 flex items-center space-x-2">
                      <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                      <span>Baseline B: Behavioral Sequence Engine</span>
                    </td>
                    <td className="py-3 px-3 text-center">{benchmark.comparison.sequence.precision.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center">{benchmark.comparison.sequence.recall.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center font-bold text-sky-400">
                      {benchmark.comparison.sequence.f1.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-400">
                      {benchmark.comparison.sequence.fpr.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-rose-400">
                      {benchmark.comparison.sequence.fnr.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-400">
                      {(benchmark.unseen_accuracy.sequence * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-3 text-right">{benchmark.comparison.sequence.avg_latency_ms} ms</td>
                  </tr>

                  {/* Baseline C: ML Anomaly Detector */}
                  <tr className="hover:bg-slate-800/40">
                    <td className="py-3 px-3 font-semibold text-slate-100 flex items-center space-x-2">
                      <span className="w-2 h-2 rounded-full bg-purple-400"></span>
                      <span>Baseline C: ML Anomaly (Isolation Forest)</span>
                    </td>
                    <td className="py-3 px-3 text-center">{benchmark.comparison.ml.precision.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center">{benchmark.comparison.ml.recall.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center font-bold text-purple-400">
                      {benchmark.comparison.ml.f1.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-400">{benchmark.comparison.ml.fpr.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center text-rose-400">{benchmark.comparison.ml.fnr.toFixed(2)}</td>
                    <td className="py-3 px-3 text-center text-purple-300 font-bold">
                      {(benchmark.unseen_accuracy.ml * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-3 text-right">{benchmark.comparison.ml.avg_latency_ms} ms</td>
                  </tr>

                  {/* Combined Approach */}
                  <tr className="bg-sky-950/20 hover:bg-sky-950/30 font-bold text-white">
                    <td className="py-3 px-3 text-sky-300 flex items-center space-x-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                      <span>Combined Multi-Engine Defense</span>
                    </td>
                    <td className="py-3 px-3 text-center text-emerald-400">
                      {benchmark.comparison.combined.precision.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-emerald-400">
                      {benchmark.comparison.combined.recall.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-emerald-400 font-extrabold text-sm">
                      {benchmark.comparison.combined.f1.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-300">
                      {benchmark.comparison.combined.fpr.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-emerald-400">
                      {benchmark.comparison.combined.fnr.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-center text-emerald-400 font-extrabold">
                      {(benchmark.unseen_accuracy.combined * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-3 text-right">{benchmark.comparison.combined.avg_latency_ms} ms</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Chart & Research Findings */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Visual Metric Chart */}
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                PRECISION / RECALL / F1 VISUAL BENCHMARK
              </h3>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} domain={[0, 1.0]} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                    <Bar dataKey="Rule" fill="#94a3b8" />
                    <Bar dataKey="Sequence" fill="#f59e0b" />
                    <Bar dataKey="ML" fill="#a855f7" />
                    <Bar dataKey="Combined" fill="#10b981" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Research Ablation Findings Card */}
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs leading-relaxed font-sans text-slate-300">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
                <Info className="w-4 h-4 text-sky-400" />
                <span>RESEARCH QUESTION & ABLATION FINDINGS</span>
              </h3>

              <div className="space-y-2.5 text-slate-300 text-[11px]">
                <p>
                  <strong>Core Finding:</strong> While deterministic rules offer zero-latency detection for known
                  signatures (e.g. <code>credentials/*</code>), they fail on unseen zero-day trajectories (recall dropped
                  without sequence/ML analysis).
                </p>
                <p>
                  <strong>Ablation on Unseen Scenarios:</strong> The ML anomaly detector correctly flagged out-of-distribution
                  behavioral drift in unseen tool-hopping sequences, yielding{' '}
                  <span className="text-emerald-400 font-mono font-bold">
                    {(benchmark.unseen_accuracy.combined * 100).toFixed(0)}%
                  </span>{' '}
                  detection when combined.
                </p>
                <p>
                  <strong>Enforcement vs Observability:</strong> The Gateway achieved{' '}
                  <span className="text-emerald-400 font-mono font-bold">
                    {(benchmark.blocking_effectiveness * 100).toFixed(0)}%
                  </span>{' '}
                  blocking effectiveness by stopping unauthorized tool intents before execution, eliminating window of
                  vulnerability.
                </p>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-16 text-center text-slate-400 font-mono text-xs border border-slate-800 rounded-xl space-y-3">
          <Activity className="w-6 h-6 animate-spin mx-auto text-sky-400" />
          <p>Loading empirical benchmark data...</p>
        </div>
      )}
    </div>
  );
};
