"use client";
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ShieldAlert, CheckCircle2 } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { API_BASE_URL } from '@/lib/api';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  
  useEffect(() => { 
    const fetchAlerts = () => {
      fetch(`${API_BASE_URL}/api/alerts`)
        .then(r => r.json())
        .then(setAlerts)
        .catch(console.error); 
    };
    
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const closeAlert = async (id: string) => {
    try {
      await fetch(`${API_BASE_URL}/api/alerts/${id}/close`, { method: 'PATCH' });
      setAlerts(alerts.map(a => a.id === id ? { ...a, status: 'CLOSED' } : a));
    } catch (e) {
      console.error(e);
    }
  };

  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filteredAlerts = filterSeverity === 'ALL'
    ? alerts
    : alerts.filter(a => a.severity === filterSeverity);

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <ShieldAlert className="text-rose-500" /> Security Alerts
        </h1>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 font-bold uppercase tracking-wider mr-2">Filter:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-widest uppercase transition-colors border ${
                filterSeverity === sev
                  ? 'bg-cyan-900/30 text-cyan-400 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                  : 'bg-[#111116] text-gray-500 border-white/5 hover:border-white/20 hover:text-gray-300'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>
      <div className="bg-[#111116] border border-white/5 rounded-xl overflow-hidden shadow-lg">
        <table className="w-full text-left text-sm text-gray-400">
          <thead className="bg-white/5 text-xs uppercase font-semibold text-gray-300">
            <tr>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Title</th>
              <th className="px-6 py-4">Source IP</th>
              <th className="px-6 py-4">Session</th>
              <th className="px-6 py-4">Time</th>
              <th className="px-6 py-4">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-gray-500 font-sans">
                    No alerts found for this severity level.
                  </td>
                </tr>
              ) : filteredAlerts.map((a, i) => (
                <motion.tr 
                  key={a.id} 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className={`hover:bg-white/[0.02] ${a.status === 'CLOSED' ? 'opacity-50 grayscale' : ''}`}
                >
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold tracking-widest ${
                      a.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/20' :
                      a.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/20' : 
                      'bg-yellow-500/20 text-yellow-400 border border-yellow-500/20'
                    }`}>{a.severity}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold tracking-widest border ${
                      a.status === 'OPEN' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                    }`}>{a.status || 'OPEN'}</span>
                  </td>
                  <td className="px-6 py-4 font-medium text-gray-200">{a.title}</td>
                  <td className="px-6 py-4 font-mono text-xs text-gray-300 hover:text-cyan-400 transition-colors">
                    <Link href={`/explorer?q=${a.src_ip}`} className="bg-black/30 rounded px-2 py-1 hover:underline">{a.src_ip}</Link>
                  </td>
                  <td className="px-6 py-4 font-mono text-cyan-400 hover:underline"><Link href={`/sessions/${a.session}`}>{a.session}</Link></td>
                  <td className="px-6 py-4 text-xs font-mono">{new Date(a.timestamp).toLocaleString()}</td>
                  <td className="px-6 py-4">
                    {a.status !== 'CLOSED' && (
                      <button 
                        onClick={() => closeAlert(a.id)}
                        className="flex items-center gap-1 text-gray-400 hover:text-emerald-400 transition-colors bg-white/5 hover:bg-emerald-900/30 px-3 py-1.5 rounded border border-white/5 hover:border-emerald-500/30"
                        title="Mark as resolved"
                      >
                        <CheckCircle2 className="w-4 h-4" /> <span className="text-xs font-semibold uppercase tracking-wider">Close</span>
                      </button>
                    )}
                  </td>
                </motion.tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
