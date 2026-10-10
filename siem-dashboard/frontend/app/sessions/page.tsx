"use client";
import { useState, useEffect } from 'react';
import { Terminal, Clock, Activity, ArrowRight } from 'lucide-react';
import { motion } from 'framer-motion';
import Link from 'next/link';

export default function SessionsIndexPage() {
  const [sessions, setSessions] = useState<any[]>([]);

  const [sortBy, setSortBy] = useState('LATEST'); // LATEST, THREAT, EVENTS

  useEffect(() => {
    fetch('http://localhost:5000/api/sessions')
      .then(r => r.json())
      .then(setSessions)
      .catch(console.error);
  }, []);

  const sortedSessions = [...sessions].sort((a, b) => {
    if (sortBy === 'THREAT') return (b.threatScore || 0) - (a.threatScore || 0);
    if (sortBy === 'EVENTS') return (b.events?.length || 0) - (a.events?.length || 0);
    return new Date(b.start_time).getTime() - new Date(a.start_time).getTime();
  });

  return (
    <div className="p-8 font-sans max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Terminal className="text-cyan-500 w-6 h-6" /> Session Activity Log
          </h1>
          <p className="text-sm text-gray-400 mt-2 ml-9">Browse all SSH honeypot connection sessions and investigate TTY replays.</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 mr-4">
            <span className="text-xs text-gray-500 font-bold uppercase tracking-wider mr-2">Sort By:</span>
            {[
              { id: 'LATEST', label: 'Latest Time' },
              { id: 'THREAT', label: 'Highest Threat' },
              { id: 'EVENTS', label: 'Most Events' }
            ].map(opt => (
              <button
                key={opt.id}
                onClick={() => setSortBy(opt.id)}
                className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-widest uppercase transition-colors border ${
                  sortBy === opt.id
                    ? 'bg-cyan-900/30 text-cyan-400 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                    : 'bg-[#111116] text-gray-500 border-white/5 hover:border-white/20 hover:text-gray-300'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <div className="bg-[#111116] border border-white/5 rounded-lg px-4 py-2 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-500 animate-pulse" />
            <span className="text-xs text-gray-400 font-semibold tracking-wider">Total Sessions: {sessions.length}</span>
          </div>
        </div>
      </div>

      <div className="bg-[#111116] border border-white/5 rounded-xl overflow-hidden shadow-lg">
        <table className="w-full text-left text-sm text-gray-400">
          <thead className="bg-[#1a1a24] text-xs uppercase font-semibold text-gray-300 border-b border-white/5">
            <tr>
              <th className="px-6 py-4">Session ID</th>
              <th className="px-6 py-4">Source IP</th>
              <th className="px-6 py-4">Geo Origin</th>
              <th className="px-6 py-4">Risk Level</th>
              <th className="px-6 py-4">Threat Score</th>
              <th className="px-6 py-4">Start Time</th>
              <th className="px-6 py-4">Events</th>
              <th className="px-6 py-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {sortedSessions.map((session, i) => (
              <motion.tr 
                key={session.id} 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(i * 0.05, 0.5) }} // Cap the delay for performance
                className="hover:bg-white/[0.02] font-mono text-xs group"
              >
                <td className="px-6 py-4 font-bold text-cyan-400">
                  <Link href={`/sessions/${session.id}`} className="hover:underline">{session.id.substring(0, 12)}...</Link>
                </td>
                <td className="px-6 py-4 text-gray-200">
                  <Link href={`/explorer?q=${session.src_ip}`} className="hover:text-cyan-400 hover:underline transition-colors">{session.src_ip}</Link>
                </td>
                <td className="px-6 py-4">
                  {session.location ? (
                    <span className="flex items-center gap-1.5 text-gray-300">
                      <span className="text-sm">{session.location.flag}</span>
                      <span className="font-semibold text-gray-200">{session.location.city}</span>,{' '}
                      <span className="text-gray-500">{session.location.countryCode}</span>
                    </span>
                  ) : (
                    <span className="text-gray-600">-</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-[10px] font-bold tracking-widest uppercase ${
                    session.riskLevel === 'CRITICAL' ? 'bg-red-950/80 text-red-400 border border-red-900/50' :
                    session.riskLevel === 'HIGH' ? 'bg-orange-950/80 text-orange-400 border border-orange-900/50' :
                    session.riskLevel === 'MEDIUM' ? 'bg-yellow-950/80 text-yellow-400 border border-yellow-900/50' :
                    'bg-white/5 text-gray-400 border border-white/10'
                  }`}>
                    {session.riskLevel || 'LOW'}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <span className="text-gray-300 font-bold">{session.threatScore || 0}</span>
                  <span className="text-gray-600">/100</span>
                </td>
                <td className="px-6 py-4 text-gray-500">{new Date(session.start_time).toLocaleString()}</td>
                <td className="px-6 py-4">
                  <span className="bg-white/5 px-2 py-1 rounded text-gray-300 border border-white/10">{session.events?.length ?? 0}</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <Link href={`/sessions/${session.id}`} className="inline-flex items-center gap-2 text-cyan-500 hover:text-cyan-400 font-sans text-xs font-bold uppercase tracking-widest transition-colors">
                    Investigate <ArrowRight className="w-3 h-3" />
                  </Link>
                </td>
              </motion.tr>
            ))}
            {sessions.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500 font-sans">No sessions recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
