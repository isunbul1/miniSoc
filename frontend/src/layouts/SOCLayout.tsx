import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  ScrollText,
  AlertTriangle,
  Network,
  FileBarChart,
  Activity,
  Menu,
  X,
  Clock,
  Radio,
} from 'lucide-react';
import { api } from '../services/api';
import { getTimezoneSuffix } from '../utils/time';

export const SOCLayout: React.FC = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [backendStatus, setBackendStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [currentTime, setCurrentTime] = useState<string>('');
  const location = useLocation();

  // Update live clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const pad = (n: number) => n.toString().padStart(2, '0');
      const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())} ${getTimezoneSuffix(now)}`;
      setCurrentTime(timeStr);
    };

    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Check backend health
  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      try {
        await api.getHealth();
        if (isMounted) setBackendStatus('online');
      } catch {
        if (isMounted) setBackendStatus('offline');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { name: 'Dashboard', to: '/', icon: LayoutDashboard },
    { name: 'Security Logs', to: '/logs', icon: ScrollText },
    { name: 'Alerts', to: '/alerts', icon: AlertTriangle },
    { name: 'MITRE ATT&CK', to: '/mitre', icon: Network, badge: 'Phase 6' },
    { name: 'Reports', to: '/reports', icon: FileBarChart, badge: 'Phase 6' },
  ];

  const getPageTitle = () => {
    if (location.pathname === '/') return 'SOC Dashboard';
    if (location.pathname.startsWith('/logs')) return 'Security Logs';
    if (location.pathname.startsWith('/alerts')) return 'Security Alerts';
    if (location.pathname.startsWith('/mitre')) return 'MITRE ATT&CK Framework';
    if (location.pathname.startsWith('/reports')) return 'Security Reports';
    return 'MiniSOC';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col md:flex-row antialiased font-sans">
      {/* Sidebar - Desktop */}
      <aside className="hidden md:flex md:w-64 flex-col bg-slate-900 border-r border-slate-800 shrink-0">
        <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800 bg-slate-900/50">
          <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.15)]">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-wider text-slate-100 flex items-center gap-1.5">
              MINI<span className="text-cyan-400">SOC</span>
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">
              Threat Detection
            </p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1.5 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-800/60 shadow-[0_0_15px_rgba(6,182,212,0.1)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`
                }
              >
                <div className="flex items-center gap-3">
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </div>
                {item.badge && (
                  <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-slate-800 text-xs text-slate-400 bg-slate-900/40">
          <div className="flex items-center justify-between">
            <span className="font-medium">Engine v0.1.0</span>
            <span className="flex items-center gap-1.5 text-emerald-400 font-mono">
              <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" /> Live
            </span>
          </div>
        </div>
      </aside>

      {/* Mobile Header */}
      <header className="md:hidden flex items-center justify-between h-14 px-4 bg-slate-900 border-b border-slate-800 z-20">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-cyan-400" />
          <span className="font-bold tracking-wider text-sm">
            MINI<span className="text-cyan-400">SOC</span>
          </span>
        </div>
        <button
          type="button"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          aria-label="Toggle navigation"
        >
          {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </header>

      {/* Mobile Drawer */}
      {isMobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-10 bg-slate-950/80 backdrop-blur-sm pt-14">
          <nav className="p-4 space-y-1.5 bg-slate-900 border-b border-slate-800">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  onClick={() => setIsMobileMenuOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center justify-between px-3.5 py-3 rounded-lg text-sm font-medium ${
                      isActive
                        ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-800/60'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                    }`
                  }
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-4 h-4" />
                    <span>{item.name}</span>
                  </div>
                  {item.badge && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
                      {item.badge}
                    </span>
                  )}
                </NavLink>
              );
            })}
          </nav>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Top bar */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/40 backdrop-blur-sm px-4 md:px-8 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="text-base font-semibold text-slate-100">{getPageTitle()}</h2>
          </div>

          <div className="flex items-center gap-4 text-xs">
            {/* Live Local Time */}
            <div className="hidden sm:flex items-center gap-1.5 text-slate-400 font-mono bg-slate-900/80 px-2.5 py-1 rounded-md border border-slate-800">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{currentTime}</span>
            </div>

            {/* Backend Health Status */}
            <div
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium ${
                backendStatus === 'online'
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                  : backendStatus === 'offline'
                  ? 'bg-rose-950/60 text-rose-400 border-rose-800/60'
                  : 'bg-amber-950/60 text-amber-400 border-amber-800/60'
              }`}
            >
              <Radio
                className={`w-3 h-3 ${
                  backendStatus === 'online'
                    ? 'text-emerald-400 animate-pulse'
                    : backendStatus === 'offline'
                    ? 'text-rose-400'
                    : 'text-amber-400'
                }`}
              />
              <span className="uppercase tracking-wider font-semibold text-[11px]">
                {backendStatus === 'online'
                  ? 'SOC ONLINE'
                  : backendStatus === 'offline'
                  ? 'BACKEND OFFLINE'
                  : 'CHECKING'}
              </span>
            </div>
          </div>
        </header>

        {/* Page Outlet */}
        <main className="flex-1 p-4 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
