"use client";
import { useEffect, useState } from 'react';
import { Search, Filter, X, ChevronDown } from 'lucide-react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';

import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import { API_BASE_URL } from '@/lib/api';

export function getEventCategory(eventId: string | null | undefined) {
    const id = typeof eventId === 'string' ? eventId.toLowerCase() : '';

    if (id.includes('login')) return { label: 'AUTH', color: 'bg-purple-500/20 text-purple-400 border-purple-500/20' };
    if (id.includes('command')) return { label: 'CMD', color: 'bg-orange-500/20 text-orange-400 border-orange-500/20' };
    if (id.includes('connect') || id.includes('closed')) return { label: 'SESS', color: 'bg-blue-500/20 text-blue-400 border-blue-500/20' };
    return { label: 'INFO', color: 'bg-gray-500/20 text-gray-400 border-gray-500/20' };
}

const CATEGORIES = ['ALL', 'AUTH', 'CMD', 'SESS', 'INFO'];

function ExplorerContent() {
  const searchParams = useSearchParams();
  const q = searchParams.get('q');

  const [events, setEvents] = useState<any[]>([]);
  const [isSearchOpen, setIsSearchOpen] = useState(!!q);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState(q || '');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  useEffect(() => { 
    const fetchEvents = () => {
      fetch(`${API_BASE_URL}/api/events`)
        .then(r => r.json())
        .then(setEvents)
        .catch(console.error); 
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  const filteredEvents = events.slice().reverse().filter(e => {
    const cat = getEventCategory(e.eventid).label;
    if (selectedCategory !== 'ALL' && cat !== selectedCategory) return false;
    
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const match = 
        (e.eventid && e.eventid.toLowerCase().includes(query)) ||
        (e.src_ip && e.src_ip.toLowerCase().includes(query)) ||
        (e.session && e.session.toLowerCase().includes(query)) ||
        (e.input && e.input.toLowerCase().includes(query)) ||
        (e.username && e.username.toLowerCase().includes(query)) ||
        (e.mitre_context && e.mitre_context.toLowerCase().includes(query));
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <Filter className="text-cyan-500 w-6 h-6" /> Event Explorer
        </h1>
        
        <div className="flex items-center gap-4">
          {/* Custom Category Dropdown */}
          <div className="relative">
            <button 
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
              className="flex items-center justify-between w-40 bg-[#111116] border border-white/5 text-gray-300 text-xs font-bold tracking-wider py-2 px-4 rounded-lg focus:outline-none focus:border-cyan-500/50 hover:bg-white/5 transition-colors shadow-lg"
            >
              <span>{selectedCategory} EVENTS</span>
              <ChevronDown className="w-4 h-4 text-gray-500" />
            </button>
            
            <AnimatePresence>
              {isDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setIsDropdownOpen(false)} />
                  <motion.div 
                    initial={{ opacity: 0, y: -5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    className="absolute right-0 top-full mt-2 w-40 bg-[#0a0a0f] border border-cyan-500/30 rounded-xl overflow-hidden shadow-[0_0_20px_rgba(6,182,212,0.15)] z-50"
                  >
                    {CATEGORIES.map(c => (
                      <button
                        key={c}
                        onClick={() => { setSelectedCategory(c); setIsDropdownOpen(false); }}
                        className={`w-full text-left px-4 py-2.5 text-[11px] font-bold tracking-widest transition-colors hover:bg-cyan-900/40 hover:text-cyan-400 ${
                          selectedCategory === c ? 'bg-cyan-900/20 text-cyan-400' : 'text-gray-400'
                        }`}
                      >
                        {c} EVENTS
                      </button>
                    ))}
                  </motion.div>
                </>
              )}
            </AnimatePresence>
          </div>
          
          {/* Toggle Search Button */}
          <button 
            onClick={() => setIsSearchOpen(!isSearchOpen)}
            className={`p-2 rounded-lg transition-colors border shadow-lg z-10 ${
              isSearchOpen 
              ? 'bg-cyan-900/30 text-cyan-400 border-cyan-500/30' 
              : 'bg-[#111116] text-gray-400 border-white/5 hover:bg-white/10 hover:text-white'
            }`}
          >
            {isSearchOpen ? <X className="w-5 h-5" /> : <Search className="w-5 h-5" />}
          </button>
        </div>
      </div>
      
      <AnimatePresence>
        {isSearchOpen && (
          <motion.div 
            initial={{ height: 0, opacity: 0, marginBottom: 0 }}
            animate={{ height: 'auto', opacity: 1, marginBottom: 24 }}
            exit={{ height: 0, opacity: 0, marginBottom: 0 }}
            className="overflow-hidden"
          >
            <div className="bg-[#0a0a0f] border border-cyan-500/30 rounded-xl p-3 flex gap-3 shadow-[0_0_20px_rgba(6,182,212,0.1)] items-center">
              <Search className="w-5 h-5 text-cyan-500 ml-2" />
              <input 
                type="text" 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by Event ID, IP, session, MITRE tactic (e.g. T1110, Brute Force), or commands..." 
                className="flex-1 bg-transparent border-none px-2 py-1 text-sm text-gray-200 focus:outline-none placeholder-gray-600 font-mono" 
                autoFocus
              />
              {searchQuery && (
                <button onClick={() => setSearchQuery('')} className="text-gray-500 hover:text-white px-3 py-1 bg-white/5 rounded text-xs font-bold uppercase tracking-wider">
                  Clear
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="bg-[#111116] border border-white/5 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
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
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-gray-500 text-sm">
                    No events found matching your filters.
                  </td>
                </tr>
              ) : filteredEvents.map((e, i) => {
                const cat = getEventCategory(e.eventid);
                return (
                  <motion.tr 
                    key={e.id || `${e.timestamp}-${i}`} 
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
                    <td className="px-6 py-3 text-rose-300 bg-black/20 rounded">{e.src_ip || '-'}</td>
                    <td className="px-6 py-3 text-blue-400 hover:underline">{e.session ? <Link href={`/sessions/${e.session}`}>{e.session}</Link> : '-'}</td>
                    <td className="px-6 py-3 text-gray-500 truncate max-w-xs">
                      {e.input || e.username || e.version || '-'}
                      {e.mitre_context && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {e.mitre_context.split(' | ').map((tag: string, tidx: number) => (
                            <span key={tidx} className="bg-blue-900/30 text-blue-400 border border-blue-800/50 px-1.5 py-0.5 rounded text-[9px] font-mono inline-block">
                              {tag.split(' ')[0]} {/* Display only the TXXXX ID */}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
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

export default function EventExplorer() {
  return (
    <Suspense fallback={<div className="p-8 text-gray-400">Loading explorer...</div>}>
      <ExplorerContent />
    </Suspense>
  );
}
