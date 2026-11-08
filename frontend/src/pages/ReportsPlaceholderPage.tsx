import React from 'react';
import { FileBarChart, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export const ReportsPlaceholderPage: React.FC = () => {
  return (
    <div className="max-w-3xl mx-auto py-12 text-center space-y-6">
      <div className="w-16 h-16 rounded-2xl bg-indigo-950/60 border border-indigo-800/80 mx-auto flex items-center justify-center text-indigo-400 shadow-[0_0_25px_rgba(99,102,241,0.15)]">
        <FileBarChart className="w-8 h-8" />
      </div>

      <div className="space-y-2">
        <span className="text-xs uppercase font-bold tracking-widest text-indigo-400 px-3 py-1 rounded-full bg-indigo-950/60 border border-indigo-800/80">
          Planned for Phase 6
        </span>
        <h1 className="text-2xl font-bold text-slate-100 mt-3">
          SOC Incident Reports & Compliance Export
        </h1>
        <p className="text-sm text-slate-400 max-w-lg mx-auto">
          Automated executive summary generation, PDF export, incident post-mortem exports, and
          compliance reporting will be activated in Phase 6.
        </p>
      </div>

      <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 text-left text-xs space-y-3 max-w-xl mx-auto">
        <h4 className="font-semibold text-slate-200 uppercase tracking-wider">
          Upcoming Reporting Features:
        </h4>
        <ul className="list-disc list-inside space-y-1.5 text-slate-400">
          <li>Automated 24h & 7-day executive threat briefing reports</li>
          <li>Detailed incident timeline export (PDF & CSV)</li>
          <li>Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) analytics</li>
          <li>Security audit compliance logging</li>
        </ul>
      </div>

      <div>
        <Link
          to="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
        >
          Return to Dashboard <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
};
