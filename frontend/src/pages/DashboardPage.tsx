import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldAlert,
  ScrollText,
  AlertOctagon,
  Flame,
  Play,
  Database,
  RefreshCw,
  Clock,
  ExternalLink,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  CartesianGrid,
  Legend,
} from 'recharts';
import { api, ApiError } from '../services/api';
import type { StatsSummary } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorMessage } from '../components/ErrorMessage';
import { EmptyState } from '../components/EmptyState';
import { SEVERITY_CONFIG } from '../utils/severity';

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<StatsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{ message: string; isNetwork?: boolean } | null>(null);

  // Dev actions states
  const [generatingLogs, setGeneratingLogs] = useState(false);
  const [runningDetection, setRunningDetection] = useState(false);
  const [actionNotification, setActionNotification] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getStatsSummary();
      setStats(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, isNetwork: err.isNetworkError });
      } else {
        setError({ message: 'Failed to load dashboard statistics.' });
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    api
      .getStatsSummary()
      .then((data) => {
        if (!ignore) {
          setStats(data);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!ignore) {
          if (err instanceof ApiError) {
            setError({ message: err.message, isNetwork: err.isNetworkError });
          } else {
            setError({ message: 'Failed to load dashboard statistics.' });
          }
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, []);

  const handleGenerateLogs = async () => {
    setActionNotification(null);
    setGeneratingLogs(true);
    try {
      const res = await api.generateLogs(42);
      setActionNotification({
        type: 'success',
        message: `Successfully generated ${res.generated_count} synthetic security logs.`,
      });
      await fetchStats();
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message
          : 'Failed to generate logs. Check server status.';
      setActionNotification({
        type: 'error',
        message: msg,
      });
    } finally {
      setGeneratingLogs(false);
    }
  };

  const handleRunDetection = async () => {
    setActionNotification(null);
    setRunningDetection(true);
    try {
      const res = await api.runDetection();
      setActionNotification({
        type: 'success',
        message: `Threat detection executed: ${res.rules_executed} rules evaluated, ${res.total_alerts_created} alert(s) created/updated.`,
      });
      await fetchStats();
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message
          : 'Failed to execute detection engine.';
      setActionNotification({
        type: 'error',
        message: msg,
      });
    } finally {
      setRunningDetection(false);
    }
  };

  if (loading && !stats) {
    return <LoadingSpinner message="Loading SOC dashboard metrics..." className="py-24" />;
  }

  if (error && !stats) {
    return (
      <div className="max-w-2xl mx-auto py-12">
        <ErrorMessage
          message={error.message}
          isNetworkError={error.isNetwork}
          onRetry={fetchStats}
        />
      </div>
    );
  }

  // Prepare data for Severity chart
  const severityOrder = ['critical', 'high', 'medium', 'low'] as const;
  const severityData = severityOrder
    .map((sev) => ({
      name: SEVERITY_CONFIG[sev].label,
      value: stats?.alerts_by_severity[sev] || 0,
      color: SEVERITY_CONFIG[sev].chartColor,
    }))
    .filter((d) => d.value > 0);

  // Prepare data for MITRE chart
  const mitreData = (stats?.alerts_by_mitre || []).map((m) => ({
    name: m.technique_id,
    fullName: `${m.technique_id} - ${m.technique_name}`,
    count: m.count,
  }));

  // Prepare data for Hourly chart
  const hourlyData = (stats?.log_counts_per_hour || []).map((h) => ({
    hour: h.hour.slice(11, 16), // "HH:MM"
    fullHour: `${h.hour} UTC`,
    events: h.count,
  }));

  const openAlertsCount = stats?.alerts_by_status?.open || 0;
  const highAndCriticalCount =
    (stats?.alerts_by_severity?.critical || 0) + (stats?.alerts_by_severity?.high || 0);

  return (
    <div className="space-y-6">
      {/* Top Banner / Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Security Operations Overview</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time threat monitoring and event correlation
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={handleGenerateLogs}
            disabled={generatingLogs}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors disabled:opacity-50"
            title="Generate synthetic attack and benign logs"
          >
            {generatingLogs ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Database className="w-3.5 h-3.5 text-cyan-400" />
            )}
            Generate Demo Logs
          </button>

          <button
            type="button"
            onClick={handleRunDetection}
            disabled={runningDetection}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm transition-colors disabled:opacity-50"
            title="Execute detection engine rules"
          >
            {runningDetection ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            Run Threat Detection
          </button>

          <button
            type="button"
            onClick={fetchStats}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800 transition-colors"
            title="Refresh statistics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Notification Banner */}
      {actionNotification && (
        <div
          data-testid="action-notification"
          className={`p-3.5 rounded-lg border text-xs font-medium flex items-center justify-between transition-all ${
            actionNotification.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300'
              : 'bg-rose-950/60 border-rose-800/80 text-rose-300'
          }`}
        >
          <span>{actionNotification.message}</span>
          <button
            type="button"
            onClick={() => setActionNotification(null)}
            className="ml-3 hover:opacity-75 font-bold"
          >
            ✕
          </button>
        </div>
      )}

      {/* Metric Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Logs */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Ingested Logs</span>
            <div className="p-2 rounded-lg bg-slate-800/80 text-cyan-400">
              <ScrollText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-slate-100">
              {stats?.total_logs.toLocaleString() ?? 0}
            </div>
            <Link
              to="/logs"
              className="mt-2 inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
            >
              Browse security logs <ExternalLink className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* Total Alerts */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Alerts</span>
            <div className="p-2 rounded-lg bg-slate-800/80 text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-slate-100">
              {stats?.total_alerts.toLocaleString() ?? 0}
            </div>
            <Link
              to="/alerts"
              className="mt-2 inline-flex items-center gap-1 text-[11px] text-amber-400 hover:text-amber-300 font-medium"
            >
              View all alerts <ExternalLink className="w-3 h-3" />
            </Link>
          </div>
        </div>

        {/* Open Incidents */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Open Incidents</span>
            <div className="p-2 rounded-lg bg-rose-950/50 text-rose-400 border border-rose-900/40">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-rose-400">
              {openAlertsCount.toLocaleString()}
            </div>
            <p className="mt-2 text-[11px] text-slate-400">Requires SOC triage</p>
          </div>
        </div>

        {/* Critical & High Alerts */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">High & Critical</span>
            <div className="p-2 rounded-lg bg-orange-950/50 text-orange-400 border border-orange-900/40">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-bold font-mono text-orange-400">
              {highAndCriticalCount.toLocaleString()}
            </div>
            <p className="mt-2 text-[11px] text-slate-400">Immediate priority threats</p>
          </div>
        </div>
      </div>

      {/* Recharts Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Alerts by Severity */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Alerts by Severity</h3>
              <p className="text-xs text-slate-400">Distribution across severity levels</p>
            </div>
          </div>

          <div className="h-64 mt-4 w-full flex items-center justify-center">
            {severityData.length === 0 ? (
              <EmptyState
                title="No Alerts Detected"
                description="Run threat detection to identify security incidents."
              />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={4}
                  >
                    {severityData.map((entry) => (
                      <Cell key={`cell-${entry.name}`} fill={entry.color} stroke="#0f172a" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                  />
                  <Legend
                    formatter={(value) => (
                      <span className="text-xs text-slate-300 font-medium">{value}</span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Chart 2: Alerts by MITRE Technique */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Alerts by MITRE ATT&CK</h3>
              <p className="text-xs text-slate-400">Technique correlation</p>
            </div>
          </div>

          <div className="h-64 mt-4 w-full flex items-center justify-center">
            {mitreData.length === 0 ? (
              <EmptyState
                title="No MITRE Alignments"
                description="Alerts correlated with MITRE techniques will show here."
              />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mitreData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis
                    dataKey="name"
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    interval={0}
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                    formatter={(value: unknown, _name: unknown, item: { payload?: { fullName?: string } }) => [
                      `${value} alert(s)`,
                      item.payload?.fullName || '',
                    ]}
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Chart 3: Hourly Log Activity (24 Hours UTC) */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Log Events Volume (Past 24 Hours)</h3>
            <p className="text-xs text-slate-400">Hourly timeline in UTC</p>
          </div>
          <span className="flex items-center gap-1.5 text-xs text-cyan-400 font-mono">
            <Clock className="w-3.5 h-3.5" /> 24h Window
          </span>
        </div>

        <div className="h-64 mt-4 w-full flex items-center justify-center">
          {hourlyData.length === 0 ? (
            <EmptyState
              title="No Log History"
              description="Ingest or generate security logs to view event activity."
            />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={hourlyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="hour" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    color: '#f8fafc',
                    fontSize: '12px',
                  }}
                  formatter={(value: unknown, _name: unknown, item: { payload?: { fullHour?: string } }) => [
                    `${value} events`,
                    item.payload?.fullHour || '',
                  ]}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
};
