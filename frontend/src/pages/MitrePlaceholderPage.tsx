import React from 'react';
import { Network, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export const MitrePlaceholderPage: React.FC = () => {
  return (
    <div className="max-w-3xl mx-auto py-12 text-center space-y-6">
      <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-800/80 mx-auto flex items-center justify-center text-cyan-400 shadow-[0_0_25px_rgba(6,182,212,0.15)]">
        <Network className="w-8 h-8" />
      </div>

      <div className="space-y-2">
        <span className="text-xs uppercase font-bold tracking-widest text-cyan-400 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/80">
          Planned for Phase 6
        </span>
        <h1 className="text-2xl font-bold text-slate-100 mt-3">
          MITRE ATT&CK Matrix & Heatmap
        </h1>
        <p className="text-sm text-slate-400 max-w-lg mx-auto">
          Interactive matrix navigation, tactic coverage scoring, and adversary technique heatmaps
          will be fully integrated in the upcoming Phase 6 milestone.
        </p>
      </div>

      <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 text-left text-xs space-y-3 max-w-xl mx-auto">
        <h4 className="font-semibold text-slate-200 uppercase tracking-wider">
          Included MITRE Reference Capabilities:
        </h4>
        <ul className="list-disc list-inside space-y-1.5 text-slate-400">
          <li>Enterprise ATT&CK matrix visualization across 14 tactics</li>
          <li>Real-time technique trigger coverage percentage</li>
          <li>Correlated threat actor profiles and detection mapping</li>
          <li>Direct technique drill-down with correlated alerts</li>
        </ul>
      </div>

      <div>
        <Link
          to="/alerts"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
        >
          View Active Correlated Alerts <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
};
