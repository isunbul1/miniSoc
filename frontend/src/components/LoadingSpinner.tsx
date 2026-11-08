import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  message = 'Loading data...',
  className = 'py-12',
}) => {
  return (
    <div
      data-testid="loading-spinner"
      className={`flex flex-col items-center justify-center gap-3 text-slate-400 ${className}`}
    >
      <Loader2 className="w-8 h-8 animate-spin text-cyan-500" />
      <span className="text-sm font-medium tracking-wide">{message}</span>
    </div>
  );
};
