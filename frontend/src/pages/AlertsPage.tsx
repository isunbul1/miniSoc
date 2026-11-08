import React, { useEffect, useState, useCallback } from 'react';
import {
  Filter,
  X,
  ChevronLeft,
  ChevronRight,
  Eye,
  RefreshCw,
} from 'lucide-react';
import { api, ApiError } from '../services/api';
import type { AlertSeverity, AlertStatus, SecurityAlert } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorMessage } from '../components/ErrorMessage';
import { EmptyState } from '../components/EmptyState';
import { CodeViewer } from '../components/CodeViewer';
import { formatLocalTime } from '../utils/time';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<{ message: string; isNetwork?: boolean } | null>(null);

  // Pagination
  const [skip, setSkip] = useState<number>(0);
  const [limit, setLimit] = useState<number>(25);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | ''>('');
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('');

  // Selected Alert for Detail Panel
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);

  // Updating status in flight
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);
  const [updateFeedback, setUpdateFeedback] = useState<string | null>(null);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getAlerts({
        skip,
        limit,
        severity: severityFilter ? (severityFilter as AlertSeverity) : undefined,
        status: statusFilter ? (statusFilter as AlertStatus) : undefined,
      });
      setAlerts(res.items);
      setTotal(res.total);
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, isNetwork: err.isNetworkError });
      } else {
        setError({ message: 'Failed to load security alerts.' });
      }
    } finally {
      setLoading(false);
    }
  }, [skip, limit, severityFilter, statusFilter]);

  useEffect(() => {
    let ignore = false;
    api
      .getAlerts({
        skip,
        limit,
        severity: severityFilter ? (severityFilter as AlertSeverity) : undefined,
        status: statusFilter ? (statusFilter as AlertStatus) : undefined,
      })
      .then((res) => {
        if (!ignore) {
          setAlerts(res.items);
          setTotal(res.total);
          setError(null);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!ignore) {
          if (err instanceof ApiError) {
            setError({ message: err.message, isNetwork: err.isNetworkError });
          } else {
            setError({ message: 'Failed to load security alerts.' });
          }
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [skip, limit, severityFilter, statusFilter]);

  const handleResetFilters = () => {
    setSeverityFilter('');
    setStatusFilter('');
    setSkip(0);
  };

  const handlePrevPage = () => {
    setSkip((prev) => Math.max(0, prev - limit));
  };

  const handleNextPage = () => {
    if (skip + limit < total) {
      setSkip((prev) => prev + limit);
    }
  };

  const handleStatusChange = async (newStatus: AlertStatus) => {
    if (!selectedAlert || selectedAlert.status === newStatus) return;

    setUpdatingStatus(true);
    setUpdateFeedback(null);
    try {
      const updated = await api.updateAlert(selectedAlert.id, { status: newStatus });
      setSelectedAlert(updated);
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setUpdateFeedback(`Status changed to "${newStatus}"`);
      setTimeout(() => setUpdateFeedback(null), 3000);
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to update alert status.';
      setUpdateFeedback(`Error: ${msg}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const currentPage = Math.floor(skip / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Security Alerts</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Deduplicated threat incidents correlated with MITRE ATT&CK techniques
          </p>
        </div>

        <button
          type="button"
          onClick={fetchAlerts}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Alerts
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          Filter Alerts
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value as AlertSeverity | '');
                setSkip(0);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as AlertStatus | '');
                setSkip(0);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          {/* Reset Filters */}
          {(severityFilter || statusFilter) && (
            <div className="flex items-center">
              <button
                type="button"
                onClick={handleResetFilters}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-800/80 rounded-lg border border-slate-700 transition-colors"
              >
                <X className="w-3.5 h-3.5" /> Clear Filters
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <ErrorMessage
          message={error.message}
          isNetworkError={error.isNetwork}
          onRetry={fetchAlerts}
        />
      )}

      {/* Alerts Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        {loading && alerts.length === 0 ? (
          <LoadingSpinner message="Querying security alert store..." className="py-20" />
        ) : alerts.length === 0 ? (
          <EmptyState
            title="No Alerts Found"
            description={
              severityFilter || statusFilter
                ? 'Try clearing or modifying your filter criteria.'
                : 'No alerts have been generated. Click "Run Threat Detection" on Dashboard to detect incidents.'
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4 w-16">ID</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Title</th>
                  <th className="py-3 px-4">MITRE Technique</th>
                  <th className="py-3 px-4 font-mono">Source IP</th>
                  <th className="py-3 px-4">Detection Time</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-800/30 transition-colors cursor-pointer group"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="py-3 px-4 font-mono text-slate-400">#{alert.id}</td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200 max-w-sm truncate select-text">
                      {alert.title}
                    </td>
                    <td className="py-3 px-4">
                      {alert.mitre_technique ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/80 font-mono text-cyan-300 text-[11px]">
                          {alert.mitre_technique.technique_id}
                        </span>
                      ) : (
                        <span className="text-slate-600 font-mono">—</span>
                      )}
                    </td>
                    {/* Plain text IP rendering strictly: never clickable link */}
                    <td className="py-3 px-4 font-mono text-slate-300 select-text">
                      {alert.source_ip || '—'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {formatLocalTime(alert.detection_time)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlert(alert);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                      >
                        <Eye className="w-3 h-3" /> Triage
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 border-t border-slate-800 bg-slate-900/60 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span>Rows per page:</span>
            <select
              value={limit}
              onChange={(e) => {
                setLimit(Number(e.target.value));
                setSkip(0);
              }}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-600"
            >
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
            <span className="ml-2 font-mono text-slate-300">
              Showing {total === 0 ? 0 : skip + 1} - {Math.min(skip + limit, total)} of {total} alerts
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="font-mono">
              Page {currentPage} of {totalPages}
            </span>
            <button
              type="button"
              onClick={handlePrevPage}
              disabled={skip === 0 || loading}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 transition-colors"
              title="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={handleNextPage}
              disabled={skip + limit >= total || loading}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 transition-colors"
              title="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Alert Detail & Triage Drawer */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col p-6 overflow-y-auto shadow-2xl">
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selectedAlert.severity} />
                  <StatusBadge status={selectedAlert.status} />
                  <span className="text-xs font-mono text-slate-500">#{selectedAlert.id}</span>
                </div>
                <h3 className="text-base font-bold text-slate-100 mt-2 select-text">
                  {selectedAlert.title}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedAlert(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="mt-5 space-y-5 flex-1">
              {/* Triage / Status Workflow Actions */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Incident Workflow Transition
                  </span>
                  {updatingStatus && (
                    <span className="text-xs text-cyan-400 flex items-center gap-1">
                      <RefreshCw className="w-3 h-3 animate-spin" /> Updating...
                    </span>
                  )}
                  {updateFeedback && (
                    <span className="text-xs text-emerald-400 font-medium">
                      {updateFeedback}
                    </span>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2" data-testid="status-action-buttons">
                  <button
                    type="button"
                    onClick={() => handleStatusChange('open')}
                    disabled={selectedAlert.status === 'open' || updatingStatus}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      selectedAlert.status === 'open'
                        ? 'bg-red-950/80 text-red-300 border-red-700 font-semibold'
                        : 'bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800'
                    }`}
                  >
                    Open
                  </button>

                  <button
                    type="button"
                    onClick={() => handleStatusChange('investigating')}
                    disabled={selectedAlert.status === 'investigating' || updatingStatus}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      selectedAlert.status === 'investigating'
                        ? 'bg-indigo-950/80 text-indigo-300 border-indigo-700 font-semibold'
                        : 'bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800'
                    }`}
                  >
                    Investigating
                  </button>

                  <button
                    type="button"
                    onClick={() => handleStatusChange('resolved')}
                    disabled={selectedAlert.status === 'resolved' || updatingStatus}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      selectedAlert.status === 'resolved'
                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700 font-semibold'
                        : 'bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800'
                    }`}
                  >
                    Resolved
                  </button>

                  <button
                    type="button"
                    onClick={() => handleStatusChange('false_positive')}
                    disabled={selectedAlert.status === 'false_positive' || updatingStatus}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                      selectedAlert.status === 'false_positive'
                        ? 'bg-zinc-800 text-zinc-300 border-zinc-600 font-semibold'
                        : 'bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800'
                    }`}
                  >
                    False Positive
                  </button>
                </div>
              </div>

              {/* Alert Metadata Grid */}
              <div className="grid grid-cols-2 gap-3 p-4 rounded-xl bg-slate-950/50 border border-slate-800 text-xs">
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Source Entity IP
                  </span>
                  <span className="mt-1 block font-mono text-slate-200 select-text">
                    {selectedAlert.source_ip || '—'}
                  </span>
                </div>

                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Detection Rule ID
                  </span>
                  <span className="mt-1 block font-mono text-cyan-400">
                    {selectedAlert.rule_id || '—'}
                  </span>
                </div>

                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Detection Time (Local)
                  </span>
                  <span className="mt-1 block font-mono text-slate-300">
                    {formatLocalTime(selectedAlert.detection_time)}
                  </span>
                </div>

                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Incident First Seen
                  </span>
                  <span className="mt-1 block font-mono text-slate-300">
                    {formatLocalTime(selectedAlert.incident_start)}
                  </span>
                </div>

                {selectedAlert.incident_key && (
                  <div className="col-span-2">
                    <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                      Incident Deduplication Key
                    </span>
                    <span className="mt-1 block font-mono text-[11px] text-slate-400 break-all select-text">
                      {selectedAlert.incident_key}
                    </span>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Correlation Box */}
              {selectedAlert.mitre_technique && (
                <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    <span>MITRE ATT&CK Matrix Correlation</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60">
                          {selectedAlert.mitre_technique.technique_id}
                        </span>
                        <span className="text-sm font-semibold text-slate-200">
                          {selectedAlert.mitre_technique.technique_name}
                        </span>
                      </div>
                      <span className="mt-1 block text-xs text-slate-400">
                        Tactic: <span className="text-slate-300 font-medium">{selectedAlert.mitre_technique.tactic}</span>
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Full Evidence Text Box */}
              <div>
                <CodeViewer
                  label="Threat Detection Evidence & Telemetry"
                  content={selectedAlert.description}
                  maxCharsCollapsed={500}
                />
              </div>
            </div>

            {/* Modal Footer */}
            <div className="pt-4 border-t border-slate-800 mt-6">
              <button
                type="button"
                onClick={() => setSelectedAlert(null)}
                className="w-full py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
              >
                Close Alert
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
