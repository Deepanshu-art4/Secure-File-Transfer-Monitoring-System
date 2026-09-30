import React, { useState, useEffect } from 'react';

const API_BASE = '/api';
const WS_URL =
  (window.location.protocol === 'https:' ? 'wss://' : 'ws://') +
  (window.location.host || '127.0.0.1:8000') +
  '/ws/telemetry';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    let ws;
    try {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setWsConnected(true);
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'INITIAL_SNAPSHOT') setStats(msg.data);
        } catch (err) {}
      };
      ws.onclose = () => setWsConnected(false);
    } catch (e) {}

    return () => {
      if (ws) ws.close();
    };
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <header className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex justify-between items-center shadow-lg">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-600 flex items-center justify-center font-bold text-white shadow-cyan-500/20 shadow-md">
            🛡️
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wider">
              SENTINEL <span className="text-cyan-400 font-mono text-sm px-1 rounded bg-cyan-950">SOC</span>
            </h1>
            <p className="text-xs text-slate-400">Secure File Transfer & Threat Monitoring System</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
          <span className="text-xs font-mono text-slate-400">{wsConnected ? 'LIVE TELEMETRY' : 'CONNECTING'}</span>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
            <div className="text-xs uppercase text-slate-400 font-bold">Total Transfers</div>
            <div className="text-3xl font-extrabold font-mono mt-2">{stats ? stats.total_transfers : 0}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
            <div className="text-xs uppercase text-slate-400 font-bold">Quarantined</div>
            <div className="text-3xl font-extrabold font-mono text-rose-400 mt-2">{stats ? stats.quarantined_count : 0}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
            <div className="text-xs uppercase text-slate-400 font-bold">Active Alerts</div>
            <div className="text-3xl font-extrabold font-mono text-amber-400 mt-2">{stats ? stats.open_alerts : 0}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
            <div className="text-xs uppercase text-slate-400 font-bold">Avg Risk Score</div>
            <div className="text-3xl font-extrabold font-mono text-cyan-400 mt-2">{stats ? stats.avg_risk_score : 0.0}</div>
          </div>
        </div>
      </main>
    </div>
  );
}
