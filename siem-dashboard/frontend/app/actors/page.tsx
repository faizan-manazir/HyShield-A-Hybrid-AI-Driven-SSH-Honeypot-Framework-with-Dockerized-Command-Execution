"use client";
import { useEffect, useState } from 'react';
import { Users, ShieldAlert, Activity, MapPin, Globe } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import { API_BASE_URL } from '@/lib/api';

export default function ActorsPage() {
  const [actors, setActors] = useState<any[]>([]);

  const [sortBy, setSortBy] = useState('EVENTS'); // EVENTS, RISK

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/actors`)
      .then(r => r.json())
      .then(setActors)
      .catch(console.error);
  }, []);

  const sortedActors = [...actors].sort((a, b) => {
    if (sortBy === 'RISK') {
      const riskScores: any = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return (riskScores[b.riskLevel] || 0) - (riskScores[a.riskLevel] || 0);
    }
    return (b.eventCount || 0) - (a.eventCount || 0);
  });

  return (
    <div className="p-8 font-sans">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <Users className="text-cyan-500 w-6 h-6" /> Source Actor Intelligence
        </h1>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 mr-4">
            <span className="text-xs text-gray-500 font-bold uppercase tracking-wider mr-2">Sort By:</span>
            {[
              { id: 'EVENTS', label: 'Most Events' },
              { id: 'RISK', label: 'Highest Risk' }
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
            <span className="text-xs text-gray-400 font-semibold tracking-wider">Tracking {actors.length} Unique Sources</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        <AnimatePresence>
          {sortedActors.map((actor, i) => (
            <motion.div 
              key={actor.ip}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.05 }}
              className="bg-[#111116] border border-white/5 rounded-xl p-6 relative overflow-hidden group shadow-lg hover:border-cyan-500/30 transition-colors"
            >
              {actor.riskLevel === 'CRITICAL' && (
                <div className="absolute top-0 right-0 w-16 h-16 bg-rose-500/10 rounded-bl-full border-b border-l border-rose-500/20 flex items-start justify-end p-2">
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                </div>
              )}
              
              <div className="flex justify-between items-start mb-4">
                <div>
                  <Link href={`/explorer?q=${actor.ip}`}>
                    <h3 className="text-lg font-mono font-bold text-white mb-0.5 group-hover:text-cyan-400 transition-colors cursor-pointer hover:underline">{actor.ip}</h3>
                  </Link>
                  <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider">Source IP Address</p>
                  {actor.location && (
                    <div className="flex items-center gap-1.5 mt-2 text-xs text-gray-300">
                      <span className="text-base">{actor.location.flag}</span>
                      <span className="font-semibold text-gray-200">{actor.location.city}</span>,
                      <span className="text-gray-400">{actor.location.countryName}</span>
                    </div>
                  )}
                </div>
                <span className={`px-2 py-1 rounded text-[10px] font-bold tracking-widest uppercase border ${
                  actor.riskLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/20' :
                  actor.riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/20' :
                  'bg-emerald-500/20 text-emerald-400 border-emerald-500/20'
                }`}>
                  {actor.riskLevel} RISK
                </span>
              </div>

              {actor.location && (
                <div className="bg-[#0a0a0f] rounded-lg p-2.5 border border-white/5 mb-4 text-[11px] font-mono">
                  <div className="flex justify-between items-center text-gray-400 mb-1">
                    <span className="flex items-center gap-1 text-gray-500"><MapPin className="w-3 h-3 text-cyan-500"/> Coordinates</span>
                    <Link href="/geomap" className="text-cyan-400 hover:text-cyan-300 hover:underline transition-colors cursor-pointer">
                      [{actor.location.lat?.toFixed(2)}, {actor.location.lng?.toFixed(2)}]
                    </Link>
                  </div>
                  <div className="flex justify-between items-center text-gray-400">
                    <span className="text-gray-500">Autonomous System</span>
                    <span className="text-gray-300 truncate max-w-[150px]">{actor.location.org}</span>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-[#0a0a0f] rounded-lg p-3 border border-white/5">
                  <p className="text-xs text-gray-500 mb-1">Total Events</p>
                  <p className="text-xl font-bold text-gray-200">{actor.eventCount}</p>
                </div>
                <div className="bg-[#0a0a0f] rounded-lg p-3 border border-white/5">
                  <p className="text-xs text-gray-500 mb-1">Duration Active</p>
                  <p className="text-sm font-semibold text-gray-300 mt-1">
                    {Math.max(1, Math.floor((new Date(actor.lastSeen).getTime() - new Date(actor.firstSeen).getTime()) / 60000))} mins
                  </p>
                </div>
              </div>

              <div className="space-y-2 text-xs text-gray-400 font-mono">
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span>First Seen</span>
                  <span className="text-gray-300">{new Date(actor.firstSeen).toLocaleString()}</span>
                </div>
                <div className="flex justify-between pt-1">
                  <span>Last Seen</span>
                  <span className="text-gray-300">{new Date(actor.lastSeen).toLocaleString()}</span>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
