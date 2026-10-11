"use client";
import { useEffect, useState } from 'react';
import { Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { API_BASE_URL } from '@/lib/api';

export function getEventCategory(eventId: string) {
    if (eventId.includes('login')) return { label: 'AUTH', color: 'bg-purple-500/20 text-purple-400 border-purple-500/20' };
    if (eventId.includes('command')) return { label: 'CMD', color: 'bg-orange-500/20 text-orange-400 border-orange-500/20' };
    if (eventId.includes('connect') || eventId.includes('closed')) return { label: 'SESS', color: 'bg-blue-500/20 text-blue-400 border-blue-500/20' };
    return { label: 'INFO', color: 'bg-gray-500/20 text-gray-400 border-gray-500/20' };
}

export default function LiveActivity() {
  const [events, setEvents] = useState<any[]>([]);
  useEffect(() => { fetch(`${API_BASE_URL}/api/events`).then(r => r.json()).then(setEvents).catch(console.error); }, []);

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
        <Activity className="text-cyan-500" /> Live Activity Stream
      </h1>
      <div className="bg-[#111116] border border-white/5 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto max-h-[750px] overflow-y-auto">
          <table className="w-full text-left text-sm text-gray-400">
            <thead className="bg-[#1a1a24] text-xs uppercase font-semibold text-gray-300 sticky top-0 border-b border-white/5 z-10">
              <tr>
                <th className="px-6 py-4">Timestamp</th>
                <th className="px-6 py-4">Category</th>
                <th className="px-6 py-4">Event ID</th>
                <th className="px-6 py-4">Source IP</th>
                <th className="px-6 py-4">Session</th>
                <th className="px-6 py-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
                {events.slice().reverse().map((e, i) => {
                  const cat = getEventCategory(e.eventid);
                  return (
                    <motion.tr 
                      key={i} 
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: Math.min(i * 0.01, 0.5) }}
                      className="hover:bg-white/[0.02] font-mono text-xs"
                    >
                      <td className="px-6 py-3 text-gray-500">{new Date(e.timestamp).toLocaleTimeString()}</td>
                      <td className="px-6 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-widest border ${cat.color}`}>{cat.label}</span>
                      </td>
                      <td className="px-6 py-3 text-cyan-400">{e.eventid}</td>
                      <td className="px-6 py-3 text-gray-300 bg-black/20 rounded">{e.src_ip || '-'}</td>
                      <td className="px-6 py-3 text-blue-400">{e.session || '-'}</td>
                      <td className="px-6 py-3 text-gray-500 truncate max-w-xs">{e.input || e.username || e.version || '-'}</td>
                    </motion.tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
