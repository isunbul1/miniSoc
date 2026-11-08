import React from 'react';
import { AlertCircle, RefreshCw, WifiOff } from 'lucide-react';

interface ErrorMessageProps {
  message: string;
  isNetworkError?: boolean;
  onRetry?: () => void;
  className?: string;
}

export const ErrorMessage: React.FC<ErrorMessageProps> = ({
  message,
  isNetworkError = false,
  onRetry,
  className = 'my-4',
}) => {
  return (
    <div
      data-testid="error-message"
      className={`rounded-lg border border-rose-900/60 bg-rose-950/40 p-4 text-rose-300 ${className}`}
    >
      <div className="flex items-start gap-3">
        {isNetworkError ? (
          <WifiOff className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
        ) : (
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
        )}
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold text-rose-200">
            {isNetworkError ? 'Connection Error' : 'Request Failed'}
          </h4>
          <p className="mt-1 text-sm text-rose-300/90 whitespace-pre-wrap break-words">{message}</p>
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-rose-900/60 hover:bg-rose-900 text-rose-200 border border-rose-700/50 transition-colors shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Retry
          </button>
        )}
      </div>
    </div>
  );
};
