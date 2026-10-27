import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { UserRole } from '../types';
import {
  Shield,
  Lock,
  User as UserIcon,
  Mail,
  KeyRound,
  ShieldCheck,
  AlertCircle,
  ArrowRight,
  Sparkles,
  Bot
} from 'lucide-react';

export const LoginPage: React.FC = () => {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');

  // Form states
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<UserRole>('ANALYST');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        await login({ username, password });
      } else {
        await register({
          username,
          email,
          password,
          full_name: fullName || undefined,
          role
        });
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = async (quickUsername: string, quickPass: string) => {
    setUsername(quickUsername);
    setPassword(quickPass);
    setError(null);
    setLoading(true);
    try {
      await login({ username: quickUsername, password: quickPass });
    } catch (err: any) {
      setError(err.message || 'Quick login failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden font-sans">
      {/* Background ambient security grid */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_var(--tw-gradient-stops))] from-sky-950/20 via-transparent to-transparent pointer-events-none" />
      <div className="absolute inset-0 bg-grid-slate-900/[0.04] bg-[bottom_1px_center] pointer-events-none" />

      {/* Main card */}
      <div className="w-full max-w-md bg-[#0d121f] border border-slate-800 rounded-2xl shadow-2xl shadow-black/80 p-8 relative z-10">
        {/* Header with shield */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 mb-4 shadow-lg shadow-sky-500/10">
            <Shield className="w-8 h-8" />
          </div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold font-mono tracking-wider text-slate-100">AEGIS AI SENTINEL</h1>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold">
              RBAC v2.0
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Zero-Trust Agent Defense & Behavioral Threat Investigation
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex rounded-lg bg-slate-900/80 p-1 border border-slate-800 mb-6">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setError(null);
            }}
            className={`flex-1 py-1.5 text-xs font-mono font-medium rounded-md transition-all ${
              mode === 'login'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            SecOps Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('register');
              setError(null);
            }}
            className={`flex-1 py-1.5 text-xs font-mono font-medium rounded-md transition-all ${
              mode === 'register'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Register Analyst
          </button>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mb-6 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-start space-x-2 text-rose-300 text-xs">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-snug">{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5">USERNAME</label>
            <div className="relative">
              <UserIcon className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin or analyst"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
              />
            </div>
          </div>

          {mode === 'register' && (
            <>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">FULL NAME</label>
                <div className="relative">
                  <UserIcon className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="e.g. Yeshwanth (Security Lead)"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">EMAIL ADDRESS</label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@enterprise.local"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">SECURITY ROLE</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setRole('ANALYST')}
                    className={`p-2.5 rounded-lg border text-left transition-all ${
                      role === 'ANALYST'
                        ? 'bg-sky-500/10 border-sky-500/50 text-sky-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-mono font-semibold">ANALYST</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Triage, inspect & simulate</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setRole('ADMIN')}
                    className={`p-2.5 rounded-lg border text-left transition-all ${
                      role === 'ADMIN'
                        ? 'bg-amber-500/10 border-amber-500/50 text-amber-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-mono font-semibold">ADMIN</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Policies, contain & benchmarks</div>
                  </button>
                </div>
              </div>
            </>
          )}

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5">PASSWORD</label>
            <div className="relative">
              <KeyRound className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
              />
            </div>
            {mode === 'register' && (
              <span className="text-[10px] text-slate-500 mt-1 block">
                Minimum 8 characters with at least one letter and one number.
              </span>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-2.5 bg-sky-500 hover:bg-sky-600 text-white font-mono text-xs font-semibold rounded-lg shadow-lg shadow-sky-500/20 flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
          >
            {loading ? (
              <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
            ) : (
              <>
                <span>{mode === 'login' ? 'AUTHENTICATE SESSION' : 'CREATE ACCOUNT'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Instant Persona Quick-Fill Box */}
        <div className="mt-8 pt-6 border-t border-slate-800">
          <div className="flex items-center space-x-1.5 text-slate-400 text-[11px] font-mono mb-3">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>INSTANT DEMO PERSONAS</span>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <button
              type="button"
              disabled={loading}
              onClick={() => handleQuickLogin('admin', 'AdminAegis2026!')}
              className="p-2.5 bg-slate-950 hover:bg-slate-900 border border-slate-800 hover:border-amber-500/40 rounded-lg text-left transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-medium text-amber-300 group-hover:text-amber-200">
                  Admin User
                </span>
                <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
              </div>
              <p className="text-[10px] text-slate-500 mt-0.5">Full containment & policy rights</p>
            </button>

            <button
              type="button"
              disabled={loading}
              onClick={() => handleQuickLogin('analyst', 'AnalystAegis2026!')}
              className="p-2.5 bg-slate-950 hover:bg-slate-900 border border-slate-800 hover:border-sky-500/40 rounded-lg text-left transition-all group"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-medium text-sky-300 group-hover:text-sky-200">
                  SecOps Analyst
                </span>
                <Bot className="w-3.5 h-3.5 text-sky-400" />
              </div>
              <p className="text-[10px] text-slate-500 mt-0.5">Telemetry, graphs & simulation</p>
            </button>
          </div>
        </div>

        {/* Footer info */}
        <div className="mt-6 text-center text-[11px] text-slate-500 font-mono">
          <Lock className="w-3 h-3 inline mr-1 text-emerald-400" />
          Encrypted JWT Session • Zero Plaintext Storage
        </div>
      </div>
    </div>
  );
};
