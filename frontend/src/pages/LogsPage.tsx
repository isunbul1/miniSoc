import React, { useEffect, useState, useCallback } from 'react';
import {
  Search,
  Filter,
  X,
  ChevronLeft,
  ChevronRight,
  Eye,
  RefreshCw,
} from 'lucide-react';
import { api, ApiError } from '../services/api';
import type { LogSeverity, SecurityLog } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ErrorMessage } from '../components/ErrorMessage';
import { EmptyState } from '../components/EmptyState';
import { CodeViewer } from '../components/CodeViewer';
import { formatLocalTime } from '../utils/time';

export const LogsPage: React.FC = () => {
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<{ message: string; isNetwork?: boolean } | null>(null);

  // Pagination
  const [skip, setSkip] = useState<number>(0);
  const [limit, setLimit] = useState<number>(25);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<LogSeverity | ''>('');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('');
  const [sourceIpFilter, setSourceIpFilter] = useState<string>('');

  // Selected Log for Detail Panel
  const [selectedLog, setSelectedLog] = useState<SecurityLog | null>(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getLogs({
        skip,
        limit,
        severity: severityFilter ? (severityFilter as LogSeverity) : undefined,
        event_type: eventTypeFilter.trim() || undefined,
        source_ip: sourceIpFilter.trim() || undefined,
      });
      setLogs(res.items);
      setTotal(res.total);
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, isNetwork: err.isNetworkError });
      } else {
        setError({ message: 'Failed to load security logs.' });
      }
    } finally {
      setLoading(false);
    }
  }, [skip, limit, severityFilter, eventTypeFilter, sourceIpFilter]);

  useEffect(() => {
    let ignore = false;
    api
      .getLogs({
        skip,
        limit,
        severity: severityFilter ? (severityFilter as LogSeverity) : undefined,
        event_type: eventTypeFilter.trim() || undefined,
        source_ip: sourceIpFilter.trim() || undefined,
      })
      .then((res) => {
        if (!ignore) {
          setLogs(res.items);
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
            setError({ message: 'Failed to load security logs.' });
          }
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [skip, limit, severityFilter, eventTypeFilter, sourceIpFilter]);

  const handleResetFilters = () => {
    setSeverityFilter('');
    setEventTypeFilter('');
    setSourceIpFilter('');
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

  const currentPage = Math.floor(skip / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Security Logs Explorer</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit trail of ingested events, authentication, and endpoint activity
          </p>
        </div>

        <button
          type="button"
          onClick={fetchLogs}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Logs
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          Filter Events
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {/* Source IP Filter */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Search Source IP..."
              value={sourceIpFilter}
              onChange={(e) => {
                setSourceIpFilter(e.target.value);
                setSkip(0);
              }}
              className="w-full pl-9 pr-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600 font-mono"
            />
          </div>

          {/* Event Type Filter */}
          <div>
            <input
              type="text"
              placeholder="Filter Event Type (e.g. auth_failure)..."
              value={eventTypeFilter}
              onChange={(e) => {
                setEventTypeFilter(e.target.value);
                setSkip(0);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600"
            />
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value as LogSeverity | '');
                setSkip(0);
              }}
              className="w-full px-3 py-2 text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-600 focus:ring-1 focus:ring-cyan-600"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Reset Filters */}
          {(severityFilter || eventTypeFilter || sourceIpFilter) && (
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
          onRetry={fetchLogs}
        />
      )}

      {/* Table Container */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        {loading && logs.length === 0 ? (
          <LoadingSpinner message="Querying security log store..." className="py-20" />
        ) : logs.length === 0 ? (
          <EmptyState
            title="No Logs Found"
            description={
              severityFilter || eventTypeFilter || sourceIpFilter
                ? 'Try clearing or modifying your filter criteria.'
                : 'No logs have been ingested yet. Click "Generate Demo Logs" on Dashboard to populate.'
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4 w-16">ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4 font-mono">Source IP</th>
                  <th className="py-3 px-4 font-mono">Destination</th>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Description / Command</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {logs.map((log) => {
                  const destStr = log.destination_port
                    ? `${log.destination_ip}:${log.destination_port}`
                    : log.destination_ip;
                  const previewText = log.command_line || log.description || '—';

                  return (
                    <tr
                      key={log.id}
                      className="hover:bg-slate-800/30 transition-colors cursor-pointer group"
                      onClick={() => setSelectedLog(log)}
                    >
                      <td className="py-3 px-4 font-mono text-slate-400">#{log.id}</td>
                      <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                        {formatLocalTime(log.timestamp)}
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={log.severity} />
                      </td>
                      <td className="py-3 px-4 font-mono text-cyan-300 font-medium">
                        {log.event_type}
                      </td>
                      {/* Plain text IP rendering strictly: never clickable link */}
                      <td className="py-3 px-4 font-mono text-slate-300 select-text">
                        {log.source_ip}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 select-text">
                        {destStr}
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {log.username || <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-xs truncate font-mono select-text">
                        {previewText}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedLog(log);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                        >
                          <Eye className="w-3 h-3" /> Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
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
              Showing {total === 0 ? 0 : skip + 1} - {Math.min(skip + limit, total)} of {total} logs
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

      {/* Row Detail Slide-Over Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full flex flex-col p-6 overflow-y-auto shadow-2xl">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <span>Log Details</span>
                  <span className="text-xs font-mono font-normal text-cyan-400">
                    #{selectedLog.id}
                  </span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Full security event inspection
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="mt-5 space-y-4 flex-1">
              {/* Key Attributes */}
              <div className="grid grid-cols-2 gap-3 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs">
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Severity
                  </span>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedLog.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Event Type
                  </span>
                  <span className="mt-1 block font-mono text-cyan-300 font-medium">
                    {selectedLog.event_type}
                  </span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Timestamp (Local)
                  </span>
                  <span className="mt-1 block font-mono text-slate-200">
                    {formatLocalTime(selectedLog.timestamp)}
                  </span>
                </div>
              </div>

              {/* Network & Entity Attributes */}
              <div className="grid grid-cols-2 gap-3 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs">
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Source IP
                  </span>
                  <span className="mt-1 block font-mono text-slate-200 select-text">
                    {selectedLog.source_ip}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Destination
                  </span>
                  <span className="mt-1 block font-mono text-slate-200 select-text">
                    {selectedLog.destination_port
                      ? `${selectedLog.destination_ip}:${selectedLog.destination_port}`
                      : selectedLog.destination_ip}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Username
                  </span>
                  <span className="mt-1 block text-slate-200">
                    {selectedLog.username || '—'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold uppercase tracking-wider block">
                    Description
                  </span>
                  <span className="mt-1 block text-slate-300">
                    {selectedLog.description || '—'}
                  </span>
                </div>
              </div>

              {/* Command Line (Plain Text, Expandable) */}
              <div>
                <CodeViewer
                  label="Process Command Line"
                  content={selectedLog.command_line}
                />
              </div>

              {/* Raw Log (Plain Text, Expandable) */}
              <div>
                <CodeViewer
                  label="Raw Log Record"
                  content={selectedLog.raw_log}
                />
              </div>
            </div>

            {/* Modal Footer */}
            <div className="pt-4 border-t border-slate-800 mt-6">
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="w-full py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
