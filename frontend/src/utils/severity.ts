/**
 * Theme & style mappings for alert/log severity and status badges.
 */

import type { AlertSeverity, AlertStatus, LogSeverity } from '../types';

export const SEVERITY_CONFIG: Record<
  LogSeverity,
  {
    label: string;
    bg: string;
    text: string;
    border: string;
    chartColor: string;
    dot: string;
  }
> = {
  critical: {
    label: 'Critical',
    bg: 'bg-rose-950/70',
    text: 'text-rose-400',
    border: 'border-rose-800/80',
    chartColor: '#f43f5e',
    dot: 'bg-rose-500',
  },
  high: {
    label: 'High',
    bg: 'bg-orange-950/70',
    text: 'text-orange-400',
    border: 'border-orange-800/80',
    chartColor: '#f97316',
    dot: 'bg-orange-500',
  },
  medium: {
    label: 'Medium',
    bg: 'bg-amber-950/70',
    text: 'text-amber-400',
    border: 'border-amber-800/80',
    chartColor: '#f59e0b',
    dot: 'bg-amber-500',
  },
  low: {
    label: 'Low',
    bg: 'bg-emerald-950/70',
    text: 'text-emerald-400',
    border: 'border-emerald-800/80',
    chartColor: '#10b981',
    dot: 'bg-emerald-500',
  },
  info: {
    label: 'Info',
    bg: 'bg-slate-800/80',
    text: 'text-slate-300',
    border: 'border-slate-700',
    chartColor: '#64748b',
    dot: 'bg-slate-400',
  },
};

export const STATUS_CONFIG: Record<
  AlertStatus,
  {
    label: string;
    bg: string;
    text: string;
    border: string;
  }
> = {
  open: {
    label: 'Open',
    bg: 'bg-red-950/60',
    text: 'text-red-400',
    border: 'border-red-800/70',
  },
  investigating: {
    label: 'Investigating',
    bg: 'bg-indigo-950/60',
    text: 'text-indigo-300',
    border: 'border-indigo-800/70',
  },
  resolved: {
    label: 'Resolved',
    bg: 'bg-emerald-950/60',
    text: 'text-emerald-400',
    border: 'border-emerald-800/70',
  },
  false_positive: {
    label: 'False Positive',
    bg: 'bg-zinc-800/80',
    text: 'text-zinc-400',
    border: 'border-zinc-700',
  },
};

export function getSeverityStyle(severity: LogSeverity | AlertSeverity) {
  return SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
}

export function getStatusStyle(status: AlertStatus) {
  return STATUS_CONFIG[status] || STATUS_CONFIG.open;
}
