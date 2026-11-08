import React from 'react';
import type { AlertStatus } from '../types';
import { getStatusStyle } from '../utils/severity';

interface StatusBadgeProps {
  status: AlertStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'sm' }) => {
  const style = getStatusStyle(status);
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm';

  return (
    <span
      data-testid={`status-badge-${status}`}
      className={`inline-flex items-center font-medium rounded-full border ${style.bg} ${style.text} ${style.border} ${sizeClasses}`}
    >
      {style.label}
    </span>
  );
};
