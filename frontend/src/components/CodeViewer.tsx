import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';

interface CodeViewerProps {
  content: string | null | undefined;
  label?: string;
  maxCharsCollapsed?: number;
  allowCopy?: boolean;
  className?: string;
}

export const CodeViewer: React.FC<CodeViewerProps> = ({
  content,
  label,
  maxCharsCollapsed = 160,
  allowCopy = true,
  className = '',
}) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!content) {
    return <span className="text-slate-500 italic text-sm">None</span>;
  }

  const isLong = content.length > maxCharsCollapsed || content.includes('\n');
  const displayText = !expanded && isLong ? `${content.slice(0, maxCharsCollapsed)}...` : content;

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`rounded-md border border-slate-800 bg-slate-950/80 p-3 ${className}`}>
      {(label || allowCopy || isLong) && (
        <div className="flex items-center justify-between gap-2 pb-2 mb-2 border-b border-slate-800/80 text-xs">
          {label ? (
            <span className="font-semibold uppercase tracking-wider text-slate-400">{label}</span>
          ) : (
            <span />
          )}
          <div className="flex items-center gap-2">
            {isLong && (
              <button
                type="button"
                onClick={() => setExpanded(!expanded)}
                className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
                data-testid="expand-toggle"
              >
                {expanded ? (
                  <>
                    <ChevronUp className="w-3.5 h-3.5" /> Collapse
                  </>
                ) : (
                  <>
                    <ChevronDown className="w-3.5 h-3.5" /> Expand
                  </>
                )}
              </button>
            )}
            {allowCopy && (
              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200 transition-colors"
                title="Copy to clipboard"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      )}
      {/* Strict plain text rendering: never dangerouslySetInnerHTML, never clickable links */}
      <pre
        data-testid="code-viewer-content"
        className="font-mono text-xs text-slate-300 whitespace-pre-wrap break-all select-text"
      >
        {displayText}
      </pre>
    </div>
  );
};
